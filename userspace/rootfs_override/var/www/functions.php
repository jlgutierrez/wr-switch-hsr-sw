<?php

//Global Variables
$etcdir="/usr/wr/etc/"; //configuration file folder for WRS
$snmpconf="snmpd.conf";
$ppsiconf="ppsi.conf";
$wrswhalconf="wrsw_hal.conf";
$sfpdatabaseconf="sfp_database.conf";
$wrdateconf="wr_date.conf";
$vlancolor = array("#27DE2A", "#B642A8", "#6E42B6", "#425DB6" , "#428DB6", "#4686B6", "#43B88B", "#42B65F", "#82B642", "#B6AE42", "#B67E42");
$MAX_PHP_FILESIZE = 40;
$phpusersfile="/usr/etc/phpusers";
$profilefile="/usr/etc/profile";
$phpinifile="/etc/php.ini";
$interfacesfile = "/usr/etc/network/interfaces";
$kconfigfile = "/wr/etc/dot-config";
$kconfigfilename = "dot-config";



/*if (empty($_SESSION["WRS_INFO"])){
	generate_wrs_info();
	include_once "data/wrs-info.php";
	$_SESSION["WRS_INFO"] = $GLOBALS["WRS_INFO"];
}*/
include "data/wrs-data.php";

//if (empty($_SESSION["WRS_TABLE_INFO"])){
	$_SESSION["WRS_TABLE_INFO"] = $GLOBALS["WRS_TABLE_INFO"];
//}

//if (empty($_SESSION["WRS_FORMS"])){
	$_SESSION["WRS_FORMS"] = $GLOBALS["WRS_FORMS"];
//}

if(empty($_SESSION["KCONFIG"])){
	load_kconfig();
}



/*
 * Displays the current status of each enpoint.
 * 
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 * @author Benoit Rat <benoit<AT>sevensols.com>
 *
 * Displays the current status of each endpoint as wr_mon tool 
 * in the swich does. It retrieves the information from wr_mon
 * and displays: master and slaves endpoints, calibration and locking 
 * status.
 * If all endpoints looks disabled (but they are not) it means
 * PTP is not running.
 * 
 */
function wrs_header_ports(){
		
	// Check whether $WRS_MANAGEMENT is set or we take the program
	// by default.

	session_start();

	if(empty($_SESSION['portsupdated'])){
		$_SESSION['portsupdated'] = intval(shell_exec("date +%s"));
	}
	 
	// Let's update endpoints info every 15 seconds.
	$currenttime = intval(shell_exec("date +%s"));
	$interval = $currenttime - $_SESSION['portsupdated'];
		
	if(!file_exists("/tmp/ports.conf") || $interval>15){
		shell_exec("/wr/bin/wr_mon -w > /tmp/ports.conf");
		$_SESSION['portsupdated'] = intval(shell_exec("date +%s"));
	}
	$ports = shell_exec("cat /tmp/ports.conf");
	$ports = explode(" ", $ports);

	// We parse and show the information comming from each endpoint.
	echo "<table border='0' align='center'  vspace='1'>";
	echo '<tr><th><h1 align=center>White-Rabbit Switch Manager</h1></th></tr>';
	echo '</table>';
	echo "<table id='sfp_panel' border='0' align='center' vspace='15'>";
	
	echo '<tr class="port">';
	$cont = 0;
	for($i=1; $i<18*3; $i=$i+3){
		
		if (strstr($ports[($i-1)],"up")){
			if (!strcmp($ports[($i)],"Master")){
				$mode="master";
			}else{
				$mode="slave";
			}
		}
		else $mode="linkdown";

		$desc=sprintf("#%02d: wr%d (%s)",$cont+1,$cont,$mode);
		echo '<th>'."<img class='".$mode."' src='img/".$mode.".png' alt='".$desc."', title='".$desc."'>".'</th>';
		$cont++;
		
	}
	echo '</tr>';
	
	echo '<tr class="status">';
	for($i=1; $i<18*3; $i=$i+3){
		
		if (!strstr($ports[($i+1)],"NoLock")){
			$mode="locked";
		}else{
			$mode="unlocked";
		}
		echo '<th>'."<img class='syntonization ".$mode."' SRC='img/".$mode.".png' alt='syntonization: ".$mode."', title = 'syntonization: ".$mode."'>";

		if (!strstr($ports[($i+2)],"Uncalibrated")){
			$mode="calibrated";
			$img="check.png";
		}else{
			$mode="uncalibrated";
			$img="uncheck.png";
		}
		echo "<img class='calibration ".$mode."' SRC='img/".$img."'  alt='".$mode."', title = '".$mode."'>".'</th>';
	}
	echo '</tr>';
	
	echo '<tr>';
	echo '</tr>';
	
	echo '</table>';

}

/*
 * Displays OS, Hardware and protocols running on the switch
 * 
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 *
 * Displays the info comming from the following commands:
 * 	 uname, wrs_version, wr_date and php.ini
 * 
 */
function wrs_main_info(){
	
	$formatID = "alternatecolor";
	$class = "altrowstable firstcol";
	$infoname = "Switch Info";
	$format = "table";
	$section = "WRS_TABLE_INFO";
	$subsection = "DASHBOARD";
	
	print_info($section, $subsection, $formatID, $class, $infoname, $format);

	// Print dinamic stuff (PPSi status, WR Date, SNMP Server & NTP)
	$class = "altrowstable firstcol";
	$formatID = "alternatecolor1";
	$infoname = "WRS Services";
	
	// Load variables
	$wr_date =  str_replace("\n","<br>",
		shell_exec("/wr/bin/wr_date -n get"));
	$PPSi = wrs_check_ptp_status() ? 
		'[<a href="ptp.php">on</A>]' : '[<a href="ptp.php">off</A>]';
	$SNMP = check_snmp_status() ? '[on] ' : '[off] '; 
	$SNMP_version = '&nbsp;&nbsp;ver. '.
		shell_exec("snmpd -v | grep version | awk '{print $3}'");
	$SNMP_port = shell_exec("cat ".$GLOBALS['etcdir']."snmpd.conf |
		grep agent | cut -d: -f3 | awk '{print $1}'");
	$NTP = $_SESSION['KCONFIG']["CONFIG_NTP_SERVER"];
	
	// Print services table
	echo '<br><table class="'.$class.'" id="'.$formatID.'" width="100%">';
	echo '<tr><th>'.$infoname.'</th></tr>';
	
	echo '<tr><td>White-Rabbit Date</td><td>'.$wr_date.'</td></tr>';
	echo '<tr><td>PPSi</td><td>'.$PPSi.'</td></tr>';
	echo '<tr><td>Net-SNMP Server</td><td>'.$SNMP.'( port '.$SNMP_port.")</td></tr>";
	echo '<tr><td>NTP Server</td><td> <a href="management.php">'.$NTP.'</td></tr>';
	echo '</table>';
	
}

function print_info($section, $subsection, $formatID, $class, $infoname, $format){
	
	switch ($format) {
		case "table":
		
			echo "<table class='".$class."'  id='".$formatID."'  width='100%'>";
			if (!empty($infoname)) echo '<tr><th>'.$infoname.'</th></tr>';
			
			foreach ($_SESSION[$section][$subsection] as $row) {
				echo "<tr>";
				echo "<td>".$row["name"]."</td>"."<td>".(($row["value"]=="") ? "(not set)" : $row['value'])."</td>";
				echo "</tr>";
			}
			echo '</table>';
		
			break;
		
		case "list":
		
			echo '<ul>';
			foreach ($_SESSION[$section][$subsection] as $row) {
				echo "<li>";
				echo $row["name"].": ".(($row["value"]=="") ? "(not set)" : $row['value']);
				echo "</li>";
			}
			echo '<ul>';
			
			break;
	}		
}

function print_form($section, $subsection, $formatID, $class, $infoname, $format){
	
	echo '<FORM method="POST">
			<table border="0" align="center" class="'.$class.'" id="'.$formatID.'">';
	if (!empty($infoname)) echo '<tr><th>'.$infoname.'</th></tr>';
	
	foreach ($_SESSION[$section][$subsection] as $row) {		
		echo "<tr>";
		echo "<td>".$row["name"]."</td>";
		echo '<td align="center"><INPUT type="text" value="'.$row["value"].'" name="'.$row["vname"].'" ></td>';
		echo "</tr>";
	}
	echo '</table>';
	
	echo '<INPUT type="submit" value="Save New Configuration" class="btn last">';	
	echo '</FORM>';				
					
	
	
}

function process_form($section, $subsection){
	
	$modified = false;
	
	if(!empty($_POST)){
		foreach ($_SESSION[$section][$subsection] as $row) {	
			$_SESSION["KCONFIG"][$row["key"]]=$_POST[$row["vname"]];
			$_SESSION[$section][$subsection][$row["value"]] = $_POST[$row["vname"]];
			$modified = true;
		}
	}
	return $modified;
}

function print_multi_form($matrix, $header, $formatID, $class, $infoname, $size){
	
	echo '<FORM method="POST">
			<table border="0" align="center" class="'.$class.'" id="'.$formatID.'"  width="100%" >';
	if (!empty($infoname)) echo '<tr><th>'.$infoname.'</th></tr>';
	
	// Printing fist line with column names.
	if (!empty($header)){
		echo "<tr class='sub'>";
		foreach ($header as $column){
			echo "<td>".($column)."</td>";
		}
		echo "</tr>";
	}
	
	$i = 0;
	
	// Printing the content of the form.
	foreach ($matrix as $array){
		$elements = explode(",",$array);
		
		$first = 0;
		echo "<tr>";
		foreach ($elements as $element){
			$column = explode("=",$element);
			if ($column[0]=="key"){
				echo '<INPUT type="hidden" value="'.$column[1].'" name="key'.$i.'" >';
			}else{
				echo '<td align="center"><INPUT size="'.$size.'" type="text" value="'.$column[1].'" name="'.$column[0].$i.'" ></td>';
				$first = 1;
			}
		}
		echo "</tr>";
		$i++;
		$first = 0;
	}
	echo '</table>';
	
	echo '<INPUT type="submit" value="Save New Configuration" class="btn last">';	
	echo '</FORM>';	
}

function process_multi_form($matrix){
	
	
	$modified = false;
	
	$i=0;
	if(!empty($_POST)){
		foreach ($matrix as $array){
			$elements = explode(",",$array);
			
			foreach ($elements as $element){
				$column = explode("=",$element);
				if($column[0]!="key"){
					$output .= preg_replace('/[0-9]+/', '', $column[0].$i)."=". $_POST[$column[0].$i].",";
				}else{
					$key = $_POST[$column[0].$i];
				}
				
				//$_SESSION["KCONFIG"][$row["key"]]=$_POST[$row["vname"]];
				//$_SESSION[$section][$subsection][$row["value"]] = $_POST[$row["vname"]];
				
			}
			$output = rtrim($output, ",");
			
			// We have the line, put it in kconfig.
			$_SESSION["KCONFIG"][$key]=$output;
			
			// Clean output
			$output="";
			$i++;
			
		}	
		$modified = true;	
	}
	
	return $modified;
}

function check_ntp_server(){	
	$ntpserver = $_SESSION['KCONFIG']["CONFIG_NTP_SERVER"];
	if(!strcmp($ntpserver, "")){
		return "not set";
	}else{
		return $ntpserver;
	}
	
}
function check_snmp_status(){
	$output = intval(shell_exec("ps aux | grep -c snmpd"));
	return ($output>2) ? 1 : 0;
	
	
}


function wrs_interface_setup(){
	
	return (!empty($_SESSION["KCONFIG"]["CONFIG_ETH0_DHCP"])) ? "dhcp" : "static";
}
/*
 * It checks whether the filesystem is writable or not.
 * 
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 *
 * It checks whether the filesystem is writable or not and prints a
 * warning message if so.
 * 
 */
function wrs_check_writeable(){

	$output = shell_exec('mount | grep "(ro,"');
	echo (!isset($output) || trim($output) == "") ? "" : "<br><font color='red'>WARNING: WRS is mounted as READ-ONLY, please contact the maintainer</font>";

}

/*
 * It checks whether the ptpd daemon is running or not.
 * 
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 *
 * It checks whether the ptpd daemon is running or not by counting 
 * the number of entries in ps command.
 * 
 * @return ptp is true or false
 * 
 */
function wrs_check_ptp_status(){
	$output = intval(shell_exec("ps aux | grep -c ppsi"));
	return ($output>2) ? 1 : 0;
}

/*
 * It modifies filesize transfer value.
 * 
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 *
 * It modifies filesize transfer value in php.ini. Two variables must be
 * modified: upload_max_filesize and post_max_size
 * 
 * @param string $size New PHP sent filename value.
 * 
 */
function php_file_transfer_size($size){
	
	// We remove the blank space
	$size=trim($size);
	
		
	// We modify fist upload_max_filesize in php.ini
	$prev_size = shell_exec("cat ".$GLOBALS['phpinifile']." | grep upload_max_filesize | awk '{print $3}'");
	$prev_size=trim($prev_size);
	$cmd = "sed -i 's/upload_max_filesize = ".$prev_size."/upload_max_filesize = ".$size."M/g' ".$GLOBALS['phpinifile'];
	shell_exec($cmd);
	
	// We modify post_max_size in php.ini
	$prev_size = shell_exec("cat ".$GLOBALS['phpinifile']." | grep post_max_size | awk '{print $3}'");
	$prev_size=trim($prev_size);
	$cmd ="sed -i 's/post_max_size = ".$prev_size."/post_max_size = ".$size."M/g' ".$GLOBALS['phpinifile'];
	shell_exec($cmd);
	shell_exec("cat ".$GLOBALS['phpinifile']." >/usr/etc/php.ini"); //We store it in /usr/etc/php.ini copy. Just in case
	
	
	//echo '<p align=center>File upload size changed to '.$size.'</p>';	
}

/*
 * It modifies each endpoint configuration 
 * 
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 *
 * It modifies each endpoint configuration by using wrs_phytool program
 * in switch. 
 * Operations: show registers, modify registers, enable/disable 
 * transmission, lock and master/grandmaster configuration.
 * 
 * @param string $option1 New PHP sent filename value.
 * @param string $endpoint Endpoint to apply new configuration.
 * 
 */
function wr_endpoint_phytool($option1, $endpoint){
	
	$cont=0;
	
	// User wants to display endpoint's registers
	if(!strcmp($option1, "dump")){
	
		$output=shell_exec("/wr/bin/wr_phytool ".$endpoint." dump");
		$ports = explode(" ", $output);
		
		echo "<table border='0' align='center'>";
		echo '<tr>';
		echo '<th>'.$endpoint.' Register</th>';
		echo '<th>Value</th>';
		echo '</tr>';
		
		for($i=7; $i<20*2; $i=$i+2){
			echo '<tr>';
			echo '<th>R'.$cont.'</th>';
			echo '<th>'.substr($ports[($i)],0,10).'</th>';
			echo '</tr>';
			$cont++;
		}
		
		echo '</tr>';
		echo '</table>';
		
		//if (!strcmp($_POST['update'], "yes")){
			//echo 'aki stamos!';
		//}
	
	// User wants to modify endpoint's registers
	} else if(!strcmp($option1, "wr")){
		
		$output=shell_exec("/wr/bin/wr_phytool ".$endpoint." dump");
		$ports = explode(" ", $output);
		
		echo '<br>';
		echo '<center></center><form  method=POST>';
		echo "<table border='0' align='center'>";
		echo '<tr>';
		echo '<th>'.$endpoint.' Registers</th>';
		echo '<th><center>Value</center></th>';
		echo '</tr>';
		
		for($i=0; $i<18; $i++){
			echo '<tr>';
			echo '<th>R'.$i.'</th>';
			echo '<th><input type="text" name="r'.$i.'" value="'.$_POST['r'.$i].'"></th>';
			echo '</tr>';
			$cont++;
		}
		
		echo '</tr>';
		echo '</table>';
		echo '<input type="hidden" name="option1" value="wr">';
		echo '<input type="hidden" name="wr" value="yes">';
		echo '<input type="hidden" name="endpoint" value="'.$endpoint.'">';
		echo '<center><input type="submit" value="Update" class="btn"></center></form><center>';
		
		if(!empty($_POST['wr'])){
			for($i=0; $i<18 ; $i++){
				if (!empty($_POST['r'.$i])){
					$cmd = '/wr/bin/wr_phytool '.$_POST['endpoint'].' wr '.dechex($i).' '.$_POST['r'.$i].'';
					$output=shell_exec($cmd);
					echo $endpoint.':R'.$i.' modified';
				}
			}
		}
	
	// User wants to enable transmission on endpoint
	} else if (!strcmp($option1, "txcal1")){
		$output=shell_exec('/wr/bin/wr_phytool '.$endpoint.' txcal 1');
		echo $endpoint.' is now transmitting calibration';
	
	// User wants to disable transmission on endpoint
	} else if(!strcmp($option1, "txcal0")){
		$output=shell_exec('/wr/bin/wr_phytool '.$endpoint.' txcal 0');
		echo $endpoint.' stopped transmitting calibration';
	
	// User wants to lock endpoint
	} else if(!strcmp($option1, "lock")){
		$output=shell_exec('/wr/bin/wr_phytool '.$endpoint.' rt lock');
		echo 'Locking finished';
	
	// User wants to make endpoint master
	} else if(!strcmp($option1, "master")){
		$output=shell_exec('/wr/bin/wr_phytool '.$endpoint.' rt master');
		echo 'Mastering finished' ;
	
	// User wants to make endpoint grandmaster	
	} else if(!strcmp($option1, "gm")){
		$output=shell_exec('/wr/bin/wr_phytool '.$endpoint.' rt gm');
		echo 'Grandmastering finished' ;
		
		
	} else if(!strcmp($option1, "hal_conf")){
		
	}
}


function wr_show_endpoint_rt_show(){

		
		$output=shell_exec('/wr/bin/wr_phytool wr0 rt show');
		$rts = nl2br($output);
		echo $rts;
}

/*
 * It returns the max. filesize that can be upload to the switch.
 * 
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 *
 * 
 * 
 */
function wrs_php_filesize(){
	
	 $size=shell_exec("cat ".$GLOBALS['phpinifile']." | grep upload_max_filesize | awk '{print $3}'"); 
	 $size=substr($size, 0, -2);
	 return $size;
	
}

/*
 * It loads binaries to the FPGA, LM32 and firmware folder.
 * 
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 *
 * It runs: 
 * 	load-virtex for loading .bin to the FPGA
 * 	load-lm32 for loading .bin to the lm32 processor
 * 	
 * 
 * 
 */
function wrs_load_files(){
		
		
		// Loading  and executing binary file with load-virtex
		if (!empty($_FILES['fpgafile']['name'])){
			$uploaddir = '/tmp/';
			$uploadfile = $uploaddir . basename($_FILES['fpgafile']['name']);
			echo '<pre>';
			if ((!strcmp(extension($_FILES['fpgafile']['name']), "bin")) && move_uploaded_file($_FILES['fpgafile']['tmp_name'], $uploadfile)) {
				echo "<center>File is valid, and was successfully uploaded.</center>\n";
				
				print "</pre>";
			
				echo '<center>Loading FPGA binary '.$_FILES['fpgafile']['name'].', please wait for the system to reboot</center>';
				$str = shell_exec("/wr/bin/load-virtex ".$uploadfile); 
				echo $str;
				
				wrs_reboot();
				
			} else {
				echo "<center>File is not valid, please upload a .bin file.</center>\n";
			}

			
			
		// Loading  and executing binary file with load-lm32
		} else if (!empty($_FILES['lm32file']['name'])){
			$uploaddir = '/tmp/';
			$uploadfile = $uploaddir . basename($_FILES['lm32file']['name']);
			echo '<pre>';
			if ((!strcmp(extension($_FILES['lm32file']['name']), "bin")) && move_uploaded_file($_FILES['lm32file']['tmp_name'], $uploadfile)) {
				echo "<center>File is valid, and was successfully uploaded.</center>\n";
				
				print "</pre>";
			
				echo '<center>Loading lm32 binary '.$_FILES['lm32file']['name'].',, please wait for the system to reboot</center>';
				$str = shell_exec("/wr/bin/load-lm32 ".$uploadfile); 
				echo $str;
				
				wrs_reboot();
				
			}  else {
				echo "<center>File is not valid, please upload a .bin file</center>\n";
			}

			
		// Loading  and copying binary file to /tmp folder on the switch.
		} else if (!empty($_FILES['file']['name'])){
			$uploaddir = '/tmp/';
			$uploadfile = $uploaddir . basename($_FILES['file']['name']);
			echo '<pre>';
			if (/*(!strcmp(extension($_FILES['file']['name']), "bin")) &&*/ move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
				echo "<center>File is valid, and was successfully uploaded to tmp folder\n";
			}  else {
				echo "<center>File is not valid, please upload a .bin file</center>\n";
			}

			echo "</pre>";
		
		} else if (!empty($_POST["size"])){
			php_file_transfer_size(htmlspecialchars($_POST["size"]));
			header ('Location: load.php');
		}

	
	
}

/*
 * Used for halting, rebooting and mounting partitions as read-only or
 * writable on switch.
 * 
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 *
 * Used for halting, rebooting and mounting partitions as read-only or
 * writable on switch.
 * 	
 * 
 */
function wrs_management(){
	
		$cmd =  htmlspecialchars($_POST["cmd"]); 


		if (!strcmp($cmd, "reboot")){
			wrs_reboot();
		} else if (!empty($_FILES['file']['name'])){
			$uploaddir = '/tmp/';
			$uploadfname= basename($_FILES['file']['name']);
			$uploadfile = $uploaddir . $uploadfname;
			echo '<pre>';
			if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
				echo '<p align=center ><font color="red"><br>Upgrade procedure will take place after reboot.<br>Please do not switch off the device during flashing procedure.</font></p>';
				if ($uploadfname=="barebox.bin" || $uploadfname=="wrs-firmware.tar" || $uploadfname=="zImage")
				{
					rename($uploadfile, "/update/".($_FILES['file']['name']));
					unlink($uploadfile);
					//Reboot switch
					sleep(1);
					wrs_reboot();
				}
				else if(substr($uploadfname,0,14)=="wr-switch-sw-v" && substr($uploadfname,-13)=="_binaries.tar")
				{
					rename($uploadfile, "/update/wrs-firmware.tar");
					unlink($uploadfile);
					//Reboot switch
					sleep(1);
					wrs_reboot();
				}
				else
				{
					echo "<center class=\"error\">Incorrect filename, please choose a filename as:<br> barebox.bin, zImage, wrs-firmware.tar or wr-switch-sw-vX.X-YYYYMMDD_binaries.tar.</center>\n";
					unlink($uploadfile);
				}
			}  else {
				echo "<center class=\"error\">Something went wrong. File was not uploaded.</center>\n";
			}

			echo "</pre>";
		} else if (!strcmp($cmd, "remoteflash")){
			
			echo '<p align=center>Downloading '.$ohwrlink.'</p>';
			
			$filename="/tmp/wr-switch-sw-v4.0-rc1-20140710_binaries.tar";
			$firmware="/update/wrs-firmware.tar";
			$ohwrlink="http://www.ohwr.org/attachments/download/3095/wr-switch-sw-v4.0-rc1-20140710_binaries.tar";
		
			file_put_contents($filename, file_get_contents($ohwrlink));
			rename($filename, $firmware);
			echo '<p align=center>File successfully downloaded. Rebooting.</p>';
			
			wrs_reboot();
			
		} else if (!empty($_FILES['kconfig']['name'])){
			
			$uploaddir = $GLOBALS['etcdir'];
			$uploadfile = $uploaddir . basename($_FILES['kconfig']['name']);
			echo '<pre>';
			if (($_FILES['kconfig']['name']==$GLOBALS['kconfigfilename']) && move_uploaded_file($_FILES['kconfig']['tmp_name'], $uploadfile)) {
				echo "<center>File is valid, and was successfully uploaded to ".$GLOBALS['etcdir']." folder. Applying changes\n";
				sleep(1);
				wrs_reboot();
			}  else {
				echo "<center>File is not valid, please upload a valid file.<br>Filename must be '".$GLOBALS['kconfigfilename']."'</center>\n";
			}

			echo "</pre>";
			
		} else if (!strcmp($cmd, "Backup")){
			
			//Prepare backup
			$backupfile=$GLOBALS['kconfigfilename'];
			shell_exec("cd ".$GLOBALS['etcdir']."; cp ".$backupfile." /var/www/download/".$backupfile);
			$backupfile="/download/$backupfile";
			
			//Download the file
			header('Location: '.$backupfile);
			 
		} else if (!strcmp($cmd, "ntp")){
			
			$ntpserver = htmlspecialchars($_POST["ntpip"]);
			
			$_SESSION["KCONFIG"]["CONFIG_NTP_SERVER"] = $ntpserver;		
			
			//Apply config
			save_kconfig();
			apply_kconfig();
			
			header('Location: management.php');
			
			
		} else if (!strcmp($cmd, "snmp")){
			
			if(check_snmp_status()){ //It is running
				
				//Stop SNMP
				shell_exec("killall snmpd");
				
			}else{ //Not running
				
				shell_exec("/etc/init.d/S80snmp > /dev/null 2>&1 &");
				
			}
			
			header('Location: management.php');
		}
		
		
		
}

/**
     * Download file
     *
     * @param string $path
     * @param string $type
     * @param string $name
     * @param bool $force_download
     * @return bool
     */
function download($path, $name = '', $type = 'application/octet-stream', $force_download = true) {

	if (!is_file($path) || connection_status() !== 0);

	if($force_download) {
		header("Cache-Control: public");
	} else {
		header("Cache-Control: no-store, no-cache, must-revalidate");
		header("Cache-Control: post-check=0, pre-check=0", false);
		header("Pragma: no-cache");
	}

	header("Expires: ".gmdate("D, d M Y H:i:s", mktime(date("H")+2, date("i"), date("s"), date("m"), date("d"), date("Y")))." GMT");
	header("Last-Modified: ".gmdate("D, d M Y H:i:s")." GMT");
	header("Content-Type: $type");
	header("Content-Length: ".(string)(filesize($path)));

	$disposition = $force_download ? 'attachment' : 'inline';

	if(trim($name) == '') {
		header("Content-Disposition: $disposition; filename=" . basename($path));
	} else {
		header("Content-Disposition: $disposition; filename=\"" . trim($name)."\"");
	}

	header("Content-Transfer-Encoding: binary\n");

	if ($file = fopen($path, 'rb')) {
		while(!feof($file) and (connection_status()==0)) {
			print(fread($file, 1024*8));
			flush();
		}
		fclose($file);
	}

	return((connection_status() == 0) && !connection_aborted());
}  

/*
 * This function configures the PTP daemon.
 * 
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 *
 * It configures PTP daemon:
 * - By default (-A -c)
 * - By changing the following values:
 * 	
 * 
 */
function wrs_ptp_configuration(){
	
	
	echo '<center>';
	
	if(!strcmp($_POST['cmd'],"ppsiupdate")){
		
		if(wrs_check_ptp_status()){ //PPSi is enabled.
			shell_exec("killall ppsi"); 	
		}else{  //PPSi is disabled.
			$ptp_command = "/wr/bin/ppsi > /dev/null 2>&1 &";
			$output = shell_exec($ptp_command); 		
		}
		header('Location: ptp.php');
		
	}
	if(!strcmp($_POST['cmd'],"ppsibootupdate")){
		
		$_SESSION["KCONFIG"]["CONFIG_PPSI"] = ($_SESSION["KCONFIG"]["CONFIG_PPSI"]=="y") ? 'n' : 'y';
		save_kconfig();
		
		header('Location: ptp.php');
		
	}
	if (!empty($_POST["clkclass"])){
		$old_value= rtrim(shell_exec("cat ".$GLOBALS['etcdir'].$GLOBALS['ppsiconf']." | grep class "));
		$new_value="clock-class ".htmlspecialchars($_POST["clkclass"]); 
		$sed = 'sed -i "s/'.$old_value.'/'.$new_value.'/g" '.$GLOBALS['etcdir'].$GLOBALS['ppsiconf'];echo $sed;
		shell_exec($sed);
		echo '<br>Clock Class changed to '.htmlspecialchars($_POST["clkclass"]);
	} 
	if (!empty($_POST["clkacc"])){
		$old_value= rtrim(shell_exec("cat ".$GLOBALS['etcdir'].$GLOBALS['ppsiconf']." | grep accuracy "));
		$new_value="clock-accuracy ".htmlspecialchars($_POST["clkacc"]);
		$sed ='sed -i "s/'.$old_value.'/'.$new_value.'/g" '.$GLOBALS['etcdir'].$GLOBALS['ppsiconf'];echo $sed;
		shell_exec($sed);
		echo '<br>Clock Accuracy changed to '.htmlspecialchars($_POST["clkacc"]);
	} 
	if ((!empty($_POST["clkclass"])) || !empty($_POST["clkacc"])){
		// Redirect & relaunch.
		echo '<br>Clock values changed. Rebooting PPSi daemon.</br';
			
		//We must relaunch ptpd too. (by default)
		shell_exec("killall ppsi"); 
		$ptp_command = "/wr/bin/ppsi > /dev/null 2>&1 &";
		$output = shell_exec($ptp_command); 
		
		header('Location: ptp.php');
		exit;

	}
	echo '</center>';
	
	
}

function wrs_vlan_configuration($input){
	
	//Stop previous daemon and delete configuration file.
	shell_exec('killall wrsw_rtud_new');
	shell_exec('rm /tmp/vlan.conf');
	
	$wrsw_rtud= '/wr/bin/wrsw_rtud_new -w 1 ';
	for ($id=0; $id<18; $id++){
		$wrsw_rtud .=  $input[$id].' ';
		
		//echo 'Endpoint '.$id.' added to VLAN'.$input[$id];
		//echo '<br>';
		shell_exec( 'echo '.$input[$id].' >>/tmp/vlan.conf');
	}
	
	$wrsw_rtud .= " > /dev/null 2>&1 &";
	shell_exec($wrsw_rtud);
	
}

/*
 * It gets the text that the help window should desplay.
 * 
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 * 	
 * 
 */
function wrs_vlan_display(){
	
	$rtu_running=shell_exec('ps aux | grep -c wrsw_rtud_new');
	$rtu_running=(int)$rtu_running;
	
	if($rtu_running >2){
		$vlan_config = shell_exec('cat /tmp/vlan.conf');
		
		echo "<br><table border='1' align='center' class='altrowstable' id='alternatecolor'>";
		echo '<tr><td><b><center>Current Configuration </center></b></td></tr>';
		
		echo '<tr><th><center>'.$vlan_config.'</center></th></tr>';
		echo '</tr></table><br>';
	}
	
}

function wrs_display_help($help_id, $name){
	
	if(!strcmp($help_id, "dashboard")){
		$message = "<p>
				<table border=0 align=center>
					<tr>
						<td><img src='./img/master.png' width='20' ></td>
						<td>The violet connector means that the endpoint is master</td>
					</tr>
					<tr>
						<td><img src='./img/slave.png' width='20'></td>
						<td>The blue connector means that the endpoint is slave</td>
					</tr>
					<tr>
						<td><img src='./img/linkdown.png' width='20'></td>
						<td>The gray connector means that the endpoint is not connected</td>
					</tr>
					<tr>
						<td><img src='./img/unlocked.png' width='20'></td>
						<td>The unlocked icon means that the endpoint is not locked.</td>
					</tr>
					<tr>
						<td><img src='./img/locked.png' width='20'></td>
						<td>The locked icon means that the endpoint is locked.</td>
					</tr>
					<tr>
						<td><img src='./img/check.png' width='20'></td>
						<td>The green check icon means that the endpoint is calibrated.</td>
					</tr>
					<tr>
						<td><img src='./img/uncheck.png' width='20'></td>
						<td>The red cross icon means that the endpoint is not calibrated.</td>
					</tr>
				
				
				</table>
				</p>";
	} else if (!strcmp($help_id, "load")){
		$message = "<p>Loading files: <br>
					- <b>Load FPGA File</b>: Loads a .bin file for the gateware on the FPGA.<br>
					- <b>Load LM32 File</b>: Loads a .bin file into the lm32 processor.<br>
					</p>";
	} else if (!strcmp($help_id, "endpoint")){
		$message = "<p>It is used to configure each point of the switch with different parameters as well as wrs_phytool program does. <br>
						First <b>select an enpoint</b>. <br>
						Then, select an option from the list: <br>
							- <b>Enable Calibration Transmission</b>: enables calibration transmission on endpoint<br>
							- <b>Disable Calibration Transmission</b>: disables calibration transmission on endpoint<br>
							- <b>See registers</b>: displays each endpoint registers (R0-R16) <br>
							- <b>Modify registers</b>: used to modify endpoint registers (R0-R16) <br>
							- <b>Lock endpoint</b>: used to lock endpoint <br>
							- <b>Make switch master</b>: Switch works as master <br>
							- <b>Make switch grandmaster</b>: Switch works as grandmaster<br>
							</p>";
	} else if (!strcmp($help_id, "login")){
		$message = "<p>login</p>";
	} else if (!strcmp($help_id, "logout")){
		$message = "<p>logout</p>";
	} else if (!strcmp($help_id, "management")){
		$message = "<p>
			Options: <br>
			- <b>Change mode:</b> Changes switch mode to Master/GrandMaster <br>
			- <b>Reboot switch</b>: Reboots the switch <br>
			- <b>Net-SNMP Server</b>: Enables/Disables remote management using SNMP <br>
			- <b>NTP Server</b>: Sets the IP address of an external NTP server. By default it is configured as UTC, please use the second box to change it. This change is done on the webserver, not in the switch command line environment.<br>
			- <b>Load Configuration Files</b>: You can upload individual configuration files to the switch (ppsi.conf, wrsw_hal.conf, snmp.conf, sfp_database.conf or a .tar.gz file with all of them.<br>
			- <b>Backup Configuration Files</b>: Downloads a tar.gz file with all configuration files of the switch.<br>
			</p>"; 
	} else if (!strcmp($help_id, "ptp")){
		$message = "<p><b>Enable or disable PPSi service. <br>
					<b>Changing Clock CLass and Clock Accuracy fields modifies ppsi.conf file for those values and relanches the service again.</b>. <br></p>";
	} else if (!strcmp($help_id, "console")){
		$message = "<p>This is a switch console emulator windows. Use it as if you were using a ssh session.</p>";
	} else if (!strcmp($help_id, "gateware")){
		
		$msg = shell_exec("/wr/bin/wrs_version -g");
		$msg = explode("\n", $msg);
		$message .= "<ul>";

		for($i=0; $i<5; $i++){
			
			$message .= "<li>".$msg[$i]."</li>";
		}
		$message .= "</ul>";
		
	}  else if (!strcmp($help_id, "file")){
		$msg = shell_exec("cat ".$GLOBALS['etcdir'].$name);
		$msg = explode("\n", $msg);
		for($i=0; $i<count($msg); $i++){
			
			$message .= $i.":   ".$msg[$i]."<br>";
		}
		
	} else if (!strcmp($help_id, "endpointmode")){
		$message = "<br><b>Change endpoint mode to master/slave/auto by clicking on one of the items.</b><br>";
		$message .= "<b>It modifies both wrsw_hal.conf and ppsi.conf files</b>";
	} else if (!strcmp($help_id, "snmp")){
		$message = "<p align=left>List of public SNMP OIDs</p><br>";
		$message .= shell_exec("snmpwalk -v1 -c public localhost");
		$message = str_replace("\n","<br>",$message);
		
	} else if (!strcmp($help_id, "vlan")){
		
		$message = "<br><b>Add new VLANs to the WRS</b>";
		$message .= "<br><b>- VID --> VLAN ID in rtud</b>";
		$message .= "<br><b>- FID --> Assign FID to configured VLAN</b>";
		$message .= "<br><b>- DROP --> Enable/Disable drop frames on VLAN</b>";
		$message .= "<br><b>- PRIO --> Sets Priority</b>";
		$message .= "<br><b>- MASK --> Mask for ports belonging to configured VLAN</b>";
		$message .= "<br><br>If you want to assign port to VLANs, please add VLANs first and then click on <strong>Assign Ports to VLANs</strong>. ";
		
	} else if (!strcmp($help_id, "vlanassignment")){
		
		$message = "<br><b>Assign ports to created VLANs</b>";
		$message .= "<br><b>VLANs ID --> VLANs ID already created in rtud</b>";
		$message .= "<br><b>Mode --> Sets mode for the endpoint:</b>";
		$message .= "<br><b><ul><li>Access --> tags untagged frames, drops tagged frames not belinging to configured VLAN</b></li>";
		$message .= "<br><b><li>Trunk --> passes only tagged frames, drops all untagged frames</b></li>";
		$message .= "<br><b><li>Disable --> passess all frames as is</b></li>";
		$message .= "<br><b><li>Unqualified Port --> passess all frames regardless VLAN config</b></li></ul>";
		$message .= "<br><b>Priority --> sets priority for retagging</b>";
		$message .= "<br><b>Mask --> sets untag mask for port</b>";
		
		
	} else if (!strcmp($help_id, "network")){
		$message = "<br><b>Set a DHCP network interface configuration or a static one.</b>";
		$message = "<br><b>If you set a static configuration, you have to define: </b>";
		$message .= "<br><b><ul><li>IP Address --> IP Address of your switch</b></li>";
		$message .= "<br><b><li>Netmask --> Netmask</b></li>";
		$message .= "<br><b><li>Network--> IP Address of your network</b></li>";
		$message .= "<br><b><li>Broadcast --> Broadcast address</b></li>";
		$message .= "<br><b><li>Gateway--> Gateway of the switch network</b></li></ul>";
		$message .= "<br><br><b>NOTE: This network configuration only works for NAND-flashed switches. If you are using a NFS server, the configurtion is set by default in busybox and it is not possible to be changed.</b>";
		
	} else if (!strcmp($help_id, "firmware")){
		$message = "<p>Firmware features: <br>
					- <b>Flash firmware</b>: It flashes a new firmware to the switch. Do it under your own risk.<br>
					</p>";
	}
	
	
	
	
	echo $message;
	
}

/*
 * Obtains the file extension that will be loaded into the switch.
 * 
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 * 	
 * 
 */
function extension($filename){
    return substr(strrchr($filename, '.'), 1);
}

/*
 * Obtains the content of wrsw_hal_file
 *  
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 * 	
 * @return $file: string containing endpoints master/slave
 * 
 */
function parse_wrsw_hal_file(){
	
	$file =  shell_exec('cat '.$GLOBALS['etcdir'].'wrsw_hal.conf | grep wr_');
	$file =  str_replace("mode =", "", $file);
	$file =  str_replace('"', "", $file);
	$file =  str_replace(';', "", $file);
	$file =  str_replace('wr_', "", $file);
	$file = explode(" ", $file);
	return $file;
}

function parse_endpoint_modes(){
	
	$modes = array();
	
	for($i = 0; $i < 18; $i++){
		$endpoint = intval($i);
		$endpoint = sprintf("%02s", $endpoint);
		$endpoint = strval($endpoint);
		
		$role = $_SESSION["KCONFIG"]["CONFIG_PORT".$endpoint."_PARAMS"];
		$role = explode(",",$role);
		$role = str_replace("role=","",$role[3]);
		
		array_push($modes,$role);			
	}	
	return $modes;
}
/*
 * Obtains the content the switch mode from wrsw_hal.conf file
 *  
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 * 	
 * @return true for GrandMaster mode, false for Master mode.
 * 
 */
function check_switch_mode(){
	$status = shell_exec("cat ".$GLOBALS['etcdir']."wrsw_hal.conf | grep -c GrandMaster");
	
	if($status>0){
		return "GrandMaster";
	} else {
		return "Master";
	}

}

/*
 * Obtains the current mode of the switch from wrsw_hal.conf file
 * and changes it from master to Grandmaster and vicecersa
 *  
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 * 	
 * 
 */
function modify_switch_mode(){
	
	if (!strcmp(check_switch_mode(), "GrandMaster")){
		$cmd = 'sed -i "s/mode = \"GrandMaster\"/mode = \"Master\"/g" '.$GLOBALS['etcdir'].'wrsw_hal.conf';
	}else{
		$cmd = 'sed -i "s/mode = \"Master\"/mode = \"GrandMaster\"/g" '.$GLOBALS['etcdir'].'wrsw_hal.conf';
	}
	shell_exec($cmd);
	
}

function session_is_started(){
	
	ob_start();
	
	$login_url = "./index.php";
	
	if (!isset($_SESSION['myusername'])) {
		echo '<br><br><br><center>Please <a href="' . $login_url . '">login.</center></a>';
		exit;
	}
	
	
}

function parse_mask2ports($vlanmask){
	$vlanmask = str_replace("0x","", $vlanmask);
	$bin = decbin(hexdec($vlanmask)); 
	$bin = strrev($bin);
	$size = strlen($bin);
	$counter = 0;
	$ports = "";
	
	for($i=0; $i<18; $i++){
		if($bin[$i]=="1"){
			$ports .= "wr".($i+1)." "; 
			$counter++;
			if($counter==4){
				$ports .= "<br>";
				$counter = 0;
			}
		}
		
	}
	
	
    return $ports; 
	
}

function echoSelectedClassIfRequestMatches($requestUri)
{
    $current_file_name = basename($_SERVER['REQUEST_URI'], ".php");

    if ($current_file_name == $requestUri)
        return 'class="selected"';
}

function wrs_reboot(){
	sleep(1);
	header ('Location: reboot.php');
}

/*
 * Parses kconfig (/wr/etc/dot-config) file and it is stored in a user
 * session variable.
 *  
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 * 
 */

function load_kconfig(){
	$_SESSION['KCONFIG'] = parse_ini_file($GLOBALS['kconfigfile']);
}

/*
 * It saves the dotconfig configuration to dotfile file
 * and changes it from master to Grandmaster and vicecersa
 *  
 * @author José Luis Gutiérrez <jlgutierrez@ugr.es>
 * @precondition: For disabling binary options, the web interface expects
 * internally a "=n". A blank space "" would think the field is string and
 * not binary. 
 * i.e, 
 * 	$_SESSION['KCONFIG'][CONFIG_PTP_WR_DEFAULT]=y; enables CONFIG_PTP_WR_DEFAULT
 * 		by adding "CONFIG_PTP_WR_DEFAULT=y"
 * 	$_SESSION['KCONFIG'][CONFIG_PTP_WR_DEFAULT]=n; disables CONFIG_PTP_WR_DEFAULT
 * 		by adding "# CONFIG_PTP_WR_DEFAULT is not set"
 * 
 */
function save_kconfig(){
	
	$file = file_get_contents($GLOBALS['kconfigfile']);
	$reading = fopen($GLOBALS['kconfigfile'], 'r');
	$writing = fopen($GLOBALS['kconfigfile'].".tmp", 'w');

	while (!feof($reading)) {
	  $line = fgets($reading);
	  $line_aux = $line;
	  $element = explode("=",$line);
	  
		// Dealing with enabled options
		if ((!empty($element)) && ($element[0]!="\n") && (!feof($reading)) && ($element[0][0]!="#")){
			if($_SESSION['KCONFIG'][$element[0]]=="y") //Already enabled binary options
				$line=$element[0].'='.$_SESSION['KCONFIG'][$element[0]]."\n";
			else if ($_SESSION['KCONFIG'][$element[0]]=="n") //Binary must be disabled
				$line="# ".$element[0]." is not set"."\n";
			else
				$line=$element[0].'="'.$_SESSION['KCONFIG'][$element[0]].'"'."\n";
		} 

		// Dealing with enabled options and comments
		if (strpos($line_aux,'is not set') !== false){
			$element = explode(" ",$line_aux);
			if (!empty($element[1]) && empty($_SESSION['KCONFIG'][$element[1]]))
				$line="# ".$element[1]." is not set"."\n";
			else if (!empty($element[1]) && !empty($_SESSION['KCONFIG'][$element[1]]))
				$line=$element[1].'='.$_SESSION['KCONFIG'][$element[1]]."\n";
		}
	  
	  fputs($writing, $line);
	}
	fclose($reading); fclose($writing);
	rename( $GLOBALS['kconfigfile'].".tmp", $GLOBALS['kconfigfile']);
}

function safefilerewrite($dotconfig, $tmpdotconfig){
	
	if ($fp = fopen($dotconfig, 'w'))
    {
        $startTime = microtime();
        do
        {            $canWrite = flock($fp, LOCK_EX);
           // If lock not obtained sleep for 0 - 100 milliseconds, to avoid collision and CPU load
           if(!$canWrite) usleep(round(rand(0, 100)*1000));
        } while ((!$canWrite)and((microtime()-$startTime) < 1000));

        //file was locked so now we can store information
        if ($canWrite)
        {            rename($tmpdotconfig, $dotconfig);
            flock($fp, LOCK_UN);
        }
        fclose($fp);
    }

}

function apply_kconfig(){
	$dotconfigapp = "/usr/wr/bin/apply_dot-config";
	shell_exec($dotconfigapp. " > /dev/null 2>&1 &");
}

	
?>
