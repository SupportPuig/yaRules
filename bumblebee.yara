rule Bumblebee {
	strings:
		$a1 = "SELECT * FROM Win32_ComputerSystem"
		$a2 = "SELECT * FROM Win32_ComputerSystemProduct"
		$a3 = "SELECT * FROM Win32_OperatingSystem"
		$a5 = "/gate"
		$a7 = "bumblebee"
	condition:
		all of them
}
