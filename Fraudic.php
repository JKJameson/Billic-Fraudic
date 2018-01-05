<?php
class Fraudic {
	public $settings = array(
		'description' => 'Billic\'s Anti-Fraud Module. Allows you to determine if a user may be malicious based on the information they provided during registration. Can be used in conjunction with AccountVerification to only allow certain payment methods for low risk users.',
	);
	function after_login($user, $password) {
		global $billic, $db;
		$ipaddress = $_SERVER['REMOTE_ADDR'];
		$ipforwardedfor = $_SERVER['X-Forwarded-For'];
		$acceptlanguage = $_SERVER['HTTP_ACCEPT_LANGUAGE'];
		$useragent = $_SERVER['HTTP_USER_AGENT'];
		$sessionid = $_COOKIE['sessionid2'];
		// has this IP address been checked before?
		$checked = false;
		$records = $db->q('SELECT `data` FROM `logs_fraudic` WHERE `userid` = ? AND `ipaddress` = ? LIMIT 3', $user['id'], $ipaddress);
		foreach ($records as $record) {
			$data = json_decode($record['data'], true);
			if (!array_key_exists('error', $data)) {
				$checked = true;
				break;
			}
		}
		if ($checked) {
			return; // we do not need to check the IP again
			
		}
		$options = array(
			CURLOPT_URL => 'https://fraud.billic.com',
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HEADER => false,
			CURLOPT_FOLLOWLOCATION => true,
			CURLOPT_USERAGENT => "Curl",
			CURLOPT_AUTOREFERER => true,
			CURLOPT_CONNECTTIMEOUT => 10,
			CURLOPT_TIMEOUT => 30,
			CURLOPT_MAXREDIRS => 10,
			CURLOPT_SSL_VERIFYHOST => true,
			CURLOPT_SSL_VERIFYPEER => false,
			CURLOPT_POST => true,
			CURLOPT_POSTFIELDS => array(
				// required fields
				'ip' => $ipaddress,
				'cc' => $user['country'],
				//'license_key' => get_config('fraudic_licensekey'),
				// user data
				'email' => hash('sha256', strtolower($user['email'])) ,
				'password' => hash('sha256', strtolower($password)) ,
				'phone' => $user['phonenumber'],
				// session data
				'sessionID' => $sessionid,
				'user_agent' => $useragent,
				'accept_language' => $acceptlanguage,
				// misc
				'forwardedIP' => $ipforwardedfor,
			) ,
		);
		$ch = curl_init();
		curl_setopt_array($ch, $options);
		$data = curl_exec($ch);
		if ($data === false) {
			$data = json_encode(array(
				'error' => curl_error($ch)
			));
		}
		$data = trim($data);
		$response = json_decode($data, true);
		if (!is_array($response)) {
			$response = array(
				'error' => 'Invalid server response',
			);
		}
		if (!array_key_exists('error', $response)) {
			if ($user['verified'] == 0 && $response['risk'] < get_config('fraudic_risk')) {
				// mark the account as lowrisk
				$db->q('UPDATE `users` SET `verified` = ? WHERE `id` = ?', '2', $user['id']);
			} else if ($user['verified'] == 2 && $response['risk'] > get_config('fraudic_risk')) {
				switch (get_config('fraudic_action')) {
					case 'require_verification':
						// mark the account as unverified
						$db->q('UPDATE `users` SET `verified` = ? WHERE `id` = ?', '0', $user['id']);
					break;
					case 'block_user':
						// block the user
						$db->q('UPDATE `users` SET `blockorders` = ? WHERE `id` = ?', '1', $user['id']);
					break;
				}
			}
		}
		$db->insert('logs_fraudic', array(
			'userid' => $user['id'],
			'timestamp' => time() ,
			'ipaddress' => $ipaddress,
			'data' => json_encode($response) ,
		));
	}
	function settings($array) {
		global $billic, $db;
		if (empty($_POST['update'])) {
			echo '<form method="POST"><input type="hidden" name="billic_ajax_module" value="Fraudic"><table class="table table-striped">';
			echo '<tr><th>Setting</th><th>Value</th></tr>';
			echo '<tr><td>Fraudic License Key</td><td><input type="text" class="form-control" name="fraudic_licensekey" value="' . safe(get_config('fraudic_licensekey')) . '"></td></tr>';
			echo '<tr><td>Maximum Risk</td><td><div class="input-group" style="width: 150px"><input type="text" class="form-control" name="fraudic_risk" value="' . safe(get_config('fraudic_risk')) . '"><div class="input-group-addon">%</div></div><sup>This should be between 0% and 100%</sup></td></tr>';
			echo '<tr><td>Fraudic Action</td><td>What to do when the risk is above your requirement? <select class="form-control" name="fraudic_action">';
			echo '<option value="require_verification"' . (get_config('fraudic_action') == 'require_verification' ? ' selected' : '') . '>Mark the account as "Unverified" to prevent certian payment methods</option>';
			echo '<option value="block_user"' . (get_config('fraudic_action') == 'block_user' ? ' selected' : '') . '>Block the entire user\'s account from placing new orders</option>';
			echo '<option value="do_nothing"' . (get_config('fraudic_action') == 'do_nothing' ? ' selected' : '') . '>Do nothing</option>';
			echo '</select></td></tr>';
			echo '<tr><td colspan="2" align="center"><input type="submit" class="btn btn-default" name="update" value="Update &raquo;"></td></tr>';
			echo '</table></form>';
		} else {
			if (empty($_POST['fraudic_licensekey'])) {
				$billic->errors[] = 'License Key is required';
			}
			if ($_POST['fraudic_risk'] < 0 || $_POST['fraudic_risk'] > 100) {
				$billic->errors[] = 'Risk must be between between 0% and 100%';
			}
			if (empty($billic->errors)) {
				set_config('fraudic_licensekey', $_POST['fraudic_licensekey']);
				set_config('fraudic_risk', $_POST['fraudic_risk']);
				set_config('fraudic_action', $_POST['fraudic_action']);
				$billic->status = 'updated';
			}
		}
	}
	function global_before_header() {
		global $billic, $db;
		// add $_COOKIE['sessionid2'] for MinFraud session tracking
		if (!isset($_COOKIE['sessionid2'])) {
			setcookie('sessionid2', microtime(true) . '-' . $_SERVER['REMOTE_ADDR'], time() + 2592000); // 30 days
			
		}
	}
	function users_submodule($array) {
		global $billic, $db;
		echo '<table class="table table-striped"><tr><th>Time</th><th>IP Address</th><th>Log</th><th>ISP</th><th>Country</th><th>Risk</th></tr>';
		$records = $db->q('SELECT * FROM `logs_fraudic` WHERE `userid` = ? ORDER BY `id` DESC', $array['user']['id']);
		if (empty($records)) {
			echo '<tr><td colspan="20">User has not been checked yet</td></tr>';
		}
		foreach ($records as $record) {
			$data = json_decode($record['data'], true);
			echo '<tr><td>' . $billic->time_ago($record['timestamp']) . '&nbsp;ago</td><td>' . $record['ipaddress'] . '</td>';
			if (array_key_exists('error', $data)) {
				echo '<td colspan="5">' . $data['error'] . '</td></tr>';
				continue;
			}
			echo '<td>' . $data['log'] . '</td><td>';
			if (!empty($data['isp'])) {
				if (!empty($data['asn'])) {
					echo '<a href="http://bgp.he.net/' . $data['asn'] . '" target="_blank">';
				}
				echo $data['isp'];
				if (!empty($data['asn'])) {
					echo '</a>';
				}
			}
			echo '</td><td>';
			if ($data['cc'] != $array['user']['country']) {
				echo '<span class="label label-danger">';
			}
			$country = $billic->countries[$data['cc']];
			if (empty($country)) {
				echo $data['cc'];
			} else {
				echo $billic->flag_icon($data['cc']) . ' ' . $country;
			}
			if ($data['cc'] != $array['user']['country']) {
				echo '</span>';
			}
			echo '</td><td>';
			if ($data['risk'] > get_config('fraudic_risk')) {
				echo '<span class="label label-danger">';
			} else {
				echo '<span class="label label-success">';
			}
			echo $data['risk'] . '%</span>';
			echo '</td></tr>';
		}
		echo '</table>';
	}
}
