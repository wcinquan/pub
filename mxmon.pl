#!/usr/bin/perl

# Name: mxmon.pl
# Author: Walter Cinquanta Jr
# Description: Designed to monitor outbound email and report on consecutive deferred emails (within a period of time)
# Notes: This is a monitor with a server (open server) built into it to show the status of the domains you are sending emails to
# TODO: 
#	1) Update $defaults variables according to your mail traffic
#	2) Install POE and possibly other perl modules


use strict;
use MIME::Lite;
use Date::Manip;
use Term::ANSIColor;
    $Term::ANSIColor::AUTORESET = 1;
use Net::DNS;
use POE qw(
    Wheel::FollowTail
    Component::Server::TCP
    Wheel::ReadLine
);
use Getopt::Long;
use IO::File;
use XML::Simple;

###########################################################################

my ($maillog) = '/var/log/maillog';
my ($watchfile) = '/usr/local/etc/mxmon.hosts';
my ($logfilename) = '/var/log/mxmon.log';

my ($pidfile) = '/var/tmp/mxmon.pid';
my ($history_cache) = '/var/tmp/mxmon.history';

my ($defaults) = {		
    # Both need to be met in order to alert
    consec_fail	    => 30,		# how many times to fail (sequentally)
    check_delay	    => (30 * 60),	# how often to check (in seconds)
    cleanup_hist    => 24,		# hours to hold history

    debug => 0,
    daemon => 0,
    inittime => timestamp(),
    srv_statusport => 1337,

    use_logging => 0,

    #email settings
    from_email => 'monitor@mydomain.com',
    beep_email => 'email-defer-warn@mydomain.com',
    
    ignore_quota => 1,			# ignore deferred messages in reguards to users exceeding quota's
};

Getopt::Long::Configure("bundling", "no_ignore_case");

GetOptions(
	    "debug|d"       => \$defaults->{debug},
	    "daemon|D"	    => \$defaults->{daemon},
	    "check_delay|t" => \$defaults->{check_delay},
	    "failures|f"    => \$defaults->{consec_fail}
) || die ("You don't seem to know what your doing....");

###########################################################################
# Daemon and controllers
###########################################################################

my ($history) = {};
my $hostname = `hostname -s`;
    chomp ($hostname);

if (-e $pidfile) {
    die ("PID file '$pidfile' exists...\n");
}

if (-e $maillog && -e $watchfile) {
    if ($defaults->{daemon}) {
	my ($pid) = fork();

	if ($pid) { ## Inside the mother process:

	    my ($pf) = new IO::File($pidfile, O_CREAT | O_WRONLY, 0666) || die("UNABLE TO CREATE PID: $!\n");
	    $pf->print($pid . "\n");
	    $pf->close();
	    exit(0);
	}

	## Inside the child process...

	if ($defaults->{use_logging}) {
	    my $logfh = new IO::File($logfilename, O_CREAT | O_WRONLY | O_APPEND, 0666) || die ("UNABLE TO OPEN LOG FILE: $!\n");

	    no strict 'subs';
	    STDIN->close();
	    STDOUT->fdopen($logfh, "w")  || die "can't dup client to stdout";
	    STDERR->fdopen(STDOUT, "w") || die "can't dup stdout to stderr";

	}

	# Done this way as $pid keeps returning 0 and we can verify the pidfile actually is there...
	my ($pid_from_file) = `cat $pidfile`;
	    chomp ($pid_from_file);

	print "Starting daemon... (PID: $pid_from_file)\n";
    } else {
	print "Running in non-daemon mode\n";
    }
}

# Interrupts
$SIG{'INT' } = \&interrupt;
$SIG{'HUP' } = \&interrupt;
$SIG{'ABRT'} = \&interrupt;
$SIG{'QUIT'} = \&interrupt;
$SIG{'TRAP'} = \&interrupt;
$SIG{'STOP'} = \&interrupt;
$SIG{'TERM'} = \&interrupt;

#************************************************************
# Alert Checking
POE::Session->create(
    inline_states => {
	_start	     => \&sched_start,
	check_status => \&sched_check_status,
    }
);

#************************************************************
# Maillog tailing
POE::Session->create (
    inline_states => {
	_start	  => \&mailtail_start,
	read_line => \&mailtail_read_line,
    },
    args => [$maillog],
);

#************************************************************
# Status port (only available via localhost due to firewall)
POE::Component::Server::TCP->new(
    Alias	    => "Status_Server",
    Port	    => $defaults->{srv_statusport},
    ClientConnected => \&server_connect,
    ClientInput	    => \&client_input
);

# Start
POE::Kernel->run();

#===========================================================================
#===========================================================================
#===========================================================================
# functions are split up by the thread controller...
#===========================================================================
#===========================================================================
#===========================================================================

#*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
# Schedule functions
sub sched_start {
    my ($kernel, $heap, $session) = @_[KERNEL, HEAP, SESSION];
    print colored(timestamp() ." SCHEDULING CHECK_STATUS...($defaults->{check_delay} seconds)\n", "cyan");
    $kernel->delay(check_status => $defaults->{check_delay});
}

sub sched_check_status {
    my ($kernel, $heap, $session) = @_[KERNEL, HEAP, SESSION];
    print colored(timestamp() ." CHECKING STATUS...\n", "cyan");

    my ($alerttxt) = '';
    my ($subject) = 'EMAIL DEFER WARNING: ';

    foreach (keys (%{$history})) {
	if ($history->{$_}->{'BounceDateTime'}) { # it has bounced
	    if ($history->{$_}->{'BounceCount'} >= $defaults->{consec_fail}) { # Enough bounces to worry about
		next if ($defaults->{ignore_quota} && ($history->{$_}->{'BounceMSG'} =~ /over quota/i));

		if ($history->{$_}->{'INIT'}) { # It has had a sucessful one!


		    my $lastsuc = $history->{$_}->{'LastSuccess'} || "NEVER";
			$lastsuc = timestamp($history->{$_}->{'LastSuccess'}) unless ($lastsuc =~ /NEVER/i);

		    $alerttxt .= sprintf("%-20s %-30s %-30s\n",
			$_,
			$lastsuc,
			$history->{$_}->{'BounceCount'});

		    $subject .= $_ . ', ';

		    print $alerttxt if ($defaults->{debug});
		} else {
		    print "[STATUS] $_ not initialized... Can't report on an unsucessful domain!\n" if ($defaults->{debug});
		}
	    }
	}
    }
    if ($alerttxt) {
	$alerttxt = qq|WARNING:\n\nEmail domains been bouncing for the last |.
	    ($defaults->{check_delay} / 60) . qq| mins. \n\n| .
	     sprintf("%-20s %-30s %-30s\n",
	    "Domain", "Last Success", "Deferred since last sucess") . $alerttxt .
	    qq|\n\nTo see up-to-date information login to $hostname and do:\n\n\ttelnet localhost $defaults->{srv_statusport}| .
	    qq|\n\nhint: help\n|;
	    $subject =~ s/\, $//; #chop last ", " off subject
	send_alert($subject, $alerttxt) unless ($defaults->{debug});
    }

    # Cleaning up history hash
    print STDERR colored(timestamp() . " Attempting to cleanup history hash\n", "magenta") if ($defaults->{debug});
    foreach (keys (%{$history})) {
	my ($howold) = time() - $history->{$_}->{'LastSuccess'};
	if ($howold > $defaults->{cleanup_hist}*60*60) {
	    delete $history->{$_};
	    print STDERR colored(timestamp() ." Deleting $defaults->{cleanup_hist} hour old cache for $_ ($howold)\n", "RED");
	}
    }

    # schedule new check...
    $kernel->delay(check_status => $defaults->{check_delay});
}

#*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
# Mailtail functions
sub mailtail_start {	
    
    #precache build...
    my @watchhosts = `cat $watchfile`;

    if (-e $history_cache) {
	my $hist_in = new XML::Simple();
	my $xmlfix = {};
	my $domain = $hist_in->XMLin($history_cache, keyattr => ['domain']);
	$history = $domain->{'domain'};
	print colored(timestamp() ." Loaded history from XML CACHE $history_cache..." . scalar(keys(%{$history})) . " domains\n", "yellow");
    }

    print colored(timestamp() ." Precaching Inital mx list... '$watchfile'\n", "yellow");
    foreach (@watchhosts) {
	chomp;
	my (@mx) = mx($_);
	if (scalar(@mx)) {
	    print "^" if ($defaults->{debug});
	    $history->{$_}->{'INIT'} = 1;
	} else {
	    print "!" if ($defaults->{debug});
	}
	print "$_," if ($defaults->{debug});
    }
    print "\n" x 2 if ($defaults->{debug});
    print colored(timestamp() ." Precaching completed...\n", "yellow");
    #END precache

    # delete the file incase 2 procs try to grab same info
    unlink ($history_cache) if (-e $history_cache);

    $_[HEAP]->{wheel} = POE::Wheel::FollowTail->new(
	Filename   => $_[ARG0],
	InputEvent => 'read_line',
	ErrorEvent => 'read_line',
	SeekBack   => 1024,
      );
    $_[HEAP]->{first} = 0;
    print colored(timestamp() ." Tail Monitor started...\n", "yellow");

    my ($subject) = "MXMON INITALIZED " . timestamp();
    my ($alerttxt) = "\nMXMON has completed initialization at " . timestamp();
    send_alert($subject, $alerttxt) unless ($defaults->{debug});
}

sub mailtail_read_line {

    my $line = $_[ARG0];
    chomp ($line);

    # Look for the status line ONLY
    if ($line =~ /\sto=<?([^\s,<>]+?)>?,.*\srelay=.*\sstat=(.*)/) {
	my ($email) = $1;
	my ($stat) = $2;

	my ($to) = $email =~ /\@(.*)$/;

	if ($stat =~ /^Deferred(.*)/i) {
	    my (@mx) = mx($to);
	    if (scalar(@mx)) {
		$history->{$to}->{'BounceCount'}++;
		if ($history->{$to}->{'INIT'}) {
		    # If no "first bounce" time... mark first failure
		    if (!$history->{$to}->{'BounceDateTime'}) {
			$history->{$to}->{'BounceDateTime'} = time();

			#BAD!!! It has bounced before... increment and keep original Date...
		    }

		    $history->{$to}->{'BounceMSG'} = $stat;
		    print colored(timestamp() ." DEFERRED", "RED") . colored (" $to", "BOLD MAGENTA") .
			    " Count=>".$history->{$to}->{'BounceCount'}.
			    " (IsInit: ".$history->{$to}->{'INIT'} .
			    ") Date-Time=>" . timestamp() .
			    " LastSuccess=> " . $history->{$to}->{'LastSuccess'} . "\n"
				if ($defaults->{debug});
		}
	    } else {
		print colored(timestamp() ." No MX Records for $to... ignoring\n","magenta") if ($defaults->{debug});
	    }
	    $history->{$to}->{'DeferredCount'}++;
	}

	# Email went out
	#if ($stat =~ /Sent\s*\(ok.*\)/i) { TOOOOO GREETY... this screws up for HOTMAIL!
	if ($stat =~ /^Sent/i) { # Sent is sent... either it went or it's deferred...
	    # If it's the first time seeing something sent to this address, take note of it
	    # this will weed out the bounces for hosts that don't exist
	    unless ($history->{$to}->{'INIT'}) {
		$history->{$to}->{'INIT'} = 1;
		print colored(timestamp() ." $to: Sent history initalized...\n","yellow") if ($defaults->{debug});
	    }
	    # clear out the Bounce history
	    if ($history->{$to}->{'BounceDateTime'}) {
		print colored("$to: Clearing Bounce (" . $history->{$to}->{'BounceDateTime'} . ")\n", "yellow") if ($defaults->{debug});
		delete $history->{$to}->{'BounceDateTime'};
		delete $history->{$to}->{'BounceMSG'};
		delete $history->{$to}->{'BounceCount'};
	    }
	    $history->{$to}->{'LastSuccess'} = time();
	    print colored (timestamp() ." Success", "GREEN") . " $to\n" if ($defaults->{debug});
	    $history->{$to}->{'SuccessCount'}++;
	}
    }
}

#*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
# Server (socket localhost) functions
sub server_connect {
    my ( $session, $heap, $input ) = @_[ SESSION, HEAP, ARG0 ];

    print "got a connection from $heap->{remote_ip}\n";
    #$heap->{prompt} = $hostname . '> '; 
    $heap->{client}->put("\n\n" . "*" x 100 . "\nYou are connected to MXMON on $hostname\n\n");
}

sub client_input {
    my ( $session, $heap, $input ) = @_[ SESSION, HEAP, ARG0 ];
    print "Session ", $session->ID(), " input: $input\n" if ($defaults->{debug});
    my ($str) = "INVALID COMMAND";

    for ($input) {
	/^list$|^listdeferred$/ && do {
	    $str = sprintf("%-20s %-30s %-25s %-50s\n",
			    "Domain", "Last Success", "Consecutive Bounces", "Last Bounce MSG");
	    foreach (keys (%{$history})) {
		if ($history->{$_}->{'BounceDateTime'}) {
		    my $lastsuc = $history->{$_}->{'LastSuccess'} || "NEVER";
			$lastsuc = timestamp($history->{$_}->{'LastSuccess'}) unless ($lastsuc =~ /NEVER/i);
		    $str .= sprintf("%-20s %-30s %-25s %-50s\n",
			$_,
			$lastsuc,
			$history->{$_}->{'BounceCount'},
			$history->{$_}->{'BounceMSG'});
		    print "\t\tHISTORY: $_ = $history->{$_}\n" if ($defaults->{debug});
		}
	    }
	};
	/^reset (\S+)$/ && do {
	    my $to = $1;
	    if ($history->{$to}->{'BounceDateTime'}) {
		$str = "Clearing records for $to\n";
		delete $history->{$to}->{'BounceDateTime'};
		delete $history->{$to}->{'BounceMSG'};
		delete $history->{$to}->{'BounceCount'};
	    } else {
		$str = "No history for $to... ignoring clear\n";
	    }
	};
	# How long has the monitor been running
	/^status$/ && do {
	    $str = "Monitor settings:\n";
	    foreach my $k (keys(%$defaults)) {
		$str .= "$k = $defaults->{$k}\n";
	    }
	};
	/^info (\S+)$/ && do {
	    my $domain = $1;
	    $str = "Info for $domain:\n";
	    if ($history->{$domain}) {
		foreach my $k (keys(%{$history->{$domain}})) {
		    if ($k =~ /time|LastSuccess/i) {
			my $t = $history->{$domain}->{$k} ? timestamp($history->{$domain}->{$k}) : "NEVER";
			$str .= "\t$k = " . $t . "\n";
		    } else {
			$str .= "\t$k = $history->{$domain}->{$k}\n";
		    }
		}
	    } else {
		$str = "No bounce information for $domain\n";
	    }
	};
	/^hist(dump|count)$/ && do { #debug tools
	    for ($1) {
		/^dump$/ && do {
		    use Data::Dumper;
		    $str = Dumper($history);
		};
		/^count$/ && do {
		    $str = scalar(keys(%{$history})) . " domains in history list.\n";
		};
	    }
	};
	/^help$/ && do {
	    $str = "Help\n\tlist: List the deferring domains and the status of them...\n"
		    . "\treset <domain>: reset the count and Bounce messages for a domain\n"
		    . "\tinfo <domain>: get all cached info on a domain\n"
		    . "\tstatus: status of the MONITOR\n";
	};
	#/^quit$/ && do { $heap->{client}->put('Disconnected', 'Good Bye'); };
    }

    $heap->{client}->put(
	    "\n" . "*" x 90 . "\nCOMMAND: $input\n\n".
	    $str .
	    "\n" . "*" x 90 . "\n"
    );
}

#*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
# Internal functions
sub interrupt {
    my ($subject) = "WARNING: MXMON TERMINATED";
    my ($alerttxt) = "\nMXMON has exited with a signal " . @_ . "\nPlease investigate and restart! (Hint: Use the init script)\n"; 
    send_alert($subject, $alerttxt) unless($defaults->{debug});

    my $hist_out = new XML::Simple();
    my $xmlfix = {};
	$xmlfix->{'domain'} = $history;
    my $xml_cache = $hist_out->XMLout($xmlfix, keyattr => ['domain']);

    my ($pf) = new IO::File($history_cache, O_CREAT | O_WRONLY, 0666) || die("UNABLE TO CREATE PID: $!\n");
    $pf->print($xml_cache . "\n");
    $pf->close();

    unlink ($pidfile) if (-e $pidfile);
    die ("Caught @_ cleaning pid and exiting\n");
}

sub send_alert ($$) {
    my ($subject, $textstr) = @_;

    my $msg = MIME::Lite->new(
        From => $defaults->{from_email},
        To => $defaults->{beep_email},
        Subject => $subject,
        Type =>'multipart/mixed'
    ) or print colored(timestamp() ." Error creating multipart container: $!\n", "RED");

    $msg->attach (
        Type => 'TEXT',
        Data => $textstr
    ) or print colored(timestamp() ." Error adding the TEXT message part: $!\n", "RED");

    $msg->send;
    print colored(timestamp() ." Triggering Warning email: $subject\n", "yellow");
}

sub timestamp ($) {

    #return "[" .  UnixDate('today', "%Y%m%d %H:%M:%S") . "]";

    my ($t) = shift;
    $t = time() if ($t !~ /^\d+$/);
    my (@tp, @t2);
    my ($mon) = [ 'Jan', 'Feb', 'Mar', 'Apr',
		  'May', 'Jun', 'Jul', 'Aug',
		  'Sep', 'Oct', 'Nov', 'Dec' ];

    @tp = localtime($t);
    @t2 = ($mon->[$tp[4]], $tp[3], $tp[5] + 1900, $tp[2], $tp[1], $tp[0]);
 
    return "[" . sprintf("%s %2d, %4d %02d:%02d:%02d", @t2) . "]";
}

