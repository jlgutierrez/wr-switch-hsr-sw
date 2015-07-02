<?php include 'functions.php'; include 'head.php'; ?>
<body id="network">
<div class="main">
<div class="page">
<div class="header" >
<!--<h1>White-Rabbit Switch Tool</h1>-->
<div class="header-ports" ><?php wrs_header_ports(); ?></div>
<div class="topmenu">
	<?php include 'topmenu.php' ?>
</div>
</div>
<div class="content">
<div class="leftpanel">
<h2>Main Menu</h2>
	<?php include 'menu.php' ?>
</div>
<div class="rightpanel">
<div class="rightbody">
<h1 class="title">Network Management <a href='help.php?help_id=network' onClick='showPopup(this.href);return(false);'><img align=right src="./img/question.png"></a></h1>

	<?php session_is_started() ?>
	<?php $_SESSION['advance']=""; ?>
	
	<FORM method="POST">
	<table id="daemon" border="0" align="center">	
			<tr>
				<th align=left>eth0 Setup: </th>
				<th><input type="radio" name="networkgroup" value="DHCP" <?php if(!strcmp(wrs_interface_setup(), "dhcp")) echo "checked" ?> > DHCP <br>
					<input type="radio" name="networkgroup" value="Static" <?php if(!strcmp(wrs_interface_setup(), "static")) echo "checked" ?> > Static <br>
				<th><INPUT type="submit" value="Change" class="btn"></th>	
			</tr>
	</table>				
	</FORM>
	<br>
	
	<?php
	
		/* This will be part of the code when using dotconfig for DHCP/FIX IP
		if((empty($_POST["networkgroup"]))){
			
			$formatID = "alternatecolor";
			$class = "altrowstable firstcol";
			$infoname = "Current eth0";
			$format = "table";
			$section = "WRS_FORMS";
			$subsection = "NETWORK_SETUP";
			
			print_info($section, $subsection, $formatID, $class, $infoname, $format);
			
			echo '<br>';
			$formatID = "alternatecolor1";
			$class = "altrowstable firstcol";
			$infoname = "DNS Configuration";
			$format = "table";
			$section = "WRS_FORMS";
			$subsection = "DNS_SETUP";
			
			print_info($section, $subsection, $formatID, $class, $infoname, $format);
			
			echo '<hr><p align="right">Click <A HREF="dns.php">here</A> to modify DNS configuration</p>';
	
		}
		
		
		if ((!empty($_POST["networkgroup"])) && (!strcmp(htmlspecialchars($_POST["networkgroup"]),"DHCP"))){
			
			$DHCP_LINE = 'CONFIG_ETH0_DHCP="y"'."\n";
			file_put_contents($GLOBALS['kconfigfile'], $DHCP_LINE, FILE_APPEND | LOCK_EX);
			
			echo '<center>DHCP is now set for eth0<br>Rebooting switch</center>';
			
			//Let's reboot
			wrs_reboot();
			
		}

		if ((!empty($_POST["networkgroup"])) && (!strcmp(htmlspecialchars($_POST["networkgroup"]),"Static"))){

			$formatID = "alternatecolor";
			$class = "altrowstable firstcol";
			$infoname = "eth0";
			$format = "table";
			$section = "WRS_FORMS";
			$subsection = "NETWORK_SETUP";
			
			print_form($section, $subsection, $formatID, $class, $infoname, $format);
			
		}*/
		
		/* end of dotconfig version */
		
		if((empty($_POST["networkgroup"]))){
	
			$formatID = "alternatecolor";
			$class = "altrowstable firstcol";
			$infoname = "Current eth0";
			$format = "table";
			$section = "WRS_FORMS";
			$subsection = "NETWORK_SETUP";
			
			print_info($section, $subsection, $formatID, $class, $infoname, $format);
			
			echo '<br>';
			$formatID = "alternatecolor1";
			$class = "altrowstable firstcol";
			$infoname = "DNS Configuration";
			$format = "table";
			$section = "WRS_FORMS";
			$subsection = "DNS_SETUP";
			
			print_info($section, $subsection, $formatID, $class, $infoname, $format);
			
			echo '<hr><p align="right">Click <A HREF="dns.php">here</A> to modify DNS configuration</p>';
		}

		if ((!empty($_POST["networkgroup"])) && (!strcmp(htmlspecialchars($_POST["networkgroup"]),"DHCP"))){
			$interface_file = $GLOBALS['interfacesfile'];
			$tmpfile="/tmp/interfaces";
			shell_exec('rm '.$interface_file);
			
			$output="# Configure Loopback\nauto lo\niface lo inet loopback\n\n#Force eth0 to be configured by DHCP\nauto eth0\niface eth0 inet dhcp\n\n# Uncomment this example for static configuration\n";
			$output.="#iface eth0 inet static\n";
			$output.="#\taddress 192.168.1.10";
			$output.="\n#\tnetmask 255.255.255.0";
			$output.="\n#\tnetwork 192.168.1.0";
			$output.="\n#\tbroadcast 192.168.1.255";
			$output.="\n#\tgateway 192.168.1.1\n";
			
			$file = fopen($tmpfile,"w+");
			fwrite($file,$output);
			fclose($file);
			
			//We move the file to /usr/etc/network
			copy($tmpfile, $interface_file);
			
			echo '<center>DHCP is now set for eth0<br>Rebooting switch</center>';
			//Let's reboot
			wrs_reboot();
			
		}

		if ((!empty($_POST["networkgroup"])) && (!strcmp(htmlspecialchars($_POST["networkgroup"]),"Static"))){

			echo '<FORM method="POST">
					<table border="0" align="center" class="altrowstable" id="alternatecolor">	
						<tr>
							<td>IP Address: </td>
							<td><INPUT type="text" value="192.168.1.10" name="ip" ></td>
						</tr>
						<tr>
							<td>Netmask: </td>
							<td><INPUT type="text" value="255.255.255.0" name="netmask" ></td>
						</tr>
						<tr>
							<td>Network: </td>
							<td><INPUT  type="text" value="192.168.1.0" name="network" ></td>
						</tr>
						<tr>
							<td>Broadcast: </td>
							<td><INPUT type="text" value="192.168.1.255" name="broadcast" ></td>
						</tr>
						<tr>
							<td>Gateway: </td>
							<td><INPUT type="text" value="192.168.1.1" name="gateway" ></td>
						</tr>
					</table>
					<INPUT type="submit" value="Save New Configuration" class="btn last">
					</FORM>';
			
		}

		if ((!empty($_POST["ip"])) && (!empty($_POST["netmask"])) && (!empty($_POST["network"])) && (!empty($_POST["broadcast"])) && (!empty($_POST["gateway"]))){
			$interface_file = $GLOBALS['interfacesfile'];
			$tmpfile="/tmp/interfaces";
			shell_exec('rm '.$interface_file);
			
			$output="# Configure Loopback\nauto lo\niface lo inet loopback\n\n#Force eth0 to be configured by DHCP\n#auto eth0\n#iface eth0 inet dhcp\n\n# Uncomment this example for static configuration\n";
			$output.="iface eth0 inet static\n";
			$output.="\taddress ".$_POST["ip"];
			$output.="\n\tnetmask ".$_POST["netmask"];
			$output.="\n\tnetwork ".$_POST["network"];
			$output.="\n\tbroadcast ".$_POST["broadcast"];
			$output.="\n\tgateway ".$_POST["gateway"]."\n";
			
			$file = fopen($tmpfile,"w+");
			fwrite($file,$output);
			fclose($file);
			
			//We move the file to /usr/etc/network
			copy($tmpfile, $interface_file);
			
			echo '<center>New static configuration saved for eth0<br>Changes will take place after reboot.</center>';
			
			//Let's reboot
			wrs_reboot();
		}
	
	?>


</div>
</div>
</div>
<div class="footer">
	<?php include 'footer.php' ?>
</div>
</div>
</div>
</body>
</html>
