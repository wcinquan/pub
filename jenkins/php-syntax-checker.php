#!/usr/bin/php

<?php

// used by jenkins to syntax check all php files in the ARG directory

$options = getopt('d:v:');

//var_dump($options);
// print_r ($options);

$dir = $options['d'];
$find = shell_exec("find '$dir' -name '*.php'");
$find_out = explode("\n", $find);

#print_r ($find_out);

$isOk = 0;
$total_files = 0;

foreach ($find_out as $file) {

	if (!empty($file)) {

		$out = shell_exec("php -l '$file'");
		$info = explode("\n", $out);

		#print_r ($info);

		foreach ($info as $lines) {
			if (empty($lines)) {
				continue;
			}
			$total_files++;
			if (preg_match("/^No syntax errors detected.*/",$lines)) {
				if ($options['v'] == 'true') {
					echo " $file [\033[32mOK\033[0m]\n";
				}
				$isOk++;
			} else {
				echo " $file [\033[31mERROR\033[0m]\n";
			}

			//echo "\033[34m$lines\033[0m\n";
		}
	}
}

print "PHP-Syntax checking (php -l) $isOk/$total_files 'ok'\n";

exit();

?>

