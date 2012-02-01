#!/usr/bin/perl

BEGIN{
    $ENV{'BASH_ENV'}='';
    $ENV{'ENV'}='';
    $ENV{'LC_COLLATE'}='C';
    $ENV{'LC_CTYPE'}='C';
    $ENV{'LC_MESSAGES'}='C';
    $ENV{'LC_MONETARY'}='C';
    $ENV{'LC_NUMERIC'}='C';
    $ENV{'LC_TIME'}='C';
    $ENV{'LC_ALL'}='C';
}

use strict;
use warnings;
use Data::Dumper;
use DateTime;
use LWP::UserAgent;
use Digest::MD5;
use Archive::Tar;
use File::Copy;
use Date::Format( 'time2str' ) ;
use File::Basename;
use Config::IniFiles;

my $debug = 0;
my $verbose = 0;

sub metaprint ($$)
{
    my ($level, $display) = @_;

    print time2str("%T", time()) . " - [".uc($level)."] - " . ( (caller(1))[3] ? (caller(1))[3] :'') . " - " . ( (caller(0))[2] ? 'L'.(caller(0))[2].' - ' :'') . $display . "\n";
}

=head1

Load parameters from the ini files.

=cut

my $ini = "../ini/global.ini";
if ( ( !-f $ini ) &&  ( !-r $ini ) ) {
    metaprint 'critic', "The ini file is not found, aborting";
    exit 1;
}

my $cfg = Config::IniFiles->new( -file => $ini );

my $Temp_Path = $cfg->val( 'global', 'resources_path' );
$Temp_Path ='/tmp/' if ( !defined($Temp_Path) || ( $Temp_Path =~ /^\s*$/ ) );

my $http_proxy = $cfg->val( 'global', 'http_proxy' );

my $Bind_Env = $cfg->val( 'global', 'bind_path' );
if ( !defined($Bind_Env) || ( $Bind_Env =~ /^\s*$/ ) ) {
    metaprint 'critic', "The Bind path is empty";
    exit 1;
} elsif  ( !-d $Bind_Env ) {
    metaprint 'critic', "The Bind path doesnot exist";
    exit 1;
}

my $Bind_zone_prod = "$Temp_Path/named.conf.block";
my $Bind_zone_prod_old = "$Temp_Path/named.conf.block.old";
my $Bind_zone_new = "$Temp_Path/named.conf.block.new";
my $Bind_block_file = "$Temp_Path/blockeddomain.hosts";

my $Blacklist_tmp_file = "$Temp_Path/result";

# END of move to the ini file

my $databases = [];

push ( @{$databases}, {
        Title => 'winhelp2002',
        Activ => 1,
        URL => 'http://winhelp2002.mvps.org/hosts.txt',

        # MD5: http://winhelp2002.mvps.org/hosts.htm
        # Timestamp: http://winhelp2002.mvps.org/hosts.htm
        Category => 'winhelp2002',
        Script => 'v1',
        For => 'Bind,Squid,Shorewall',
        Local => "$Temp_Path/hosts1.txt",
    });

push ( @{$databases}, {
        Title => 'malwaredomains',
        Activ => 1,
        URL => 'http://mirror1.malwaredomains.com/files/justdomains',
        TimeStamp => 'http://mirror1.malwaredomains.com/files/timestamp',
        MD5 => 'http://mirror1.malwaredomains.com/files/md5',
        Category => 'MalwareDomains',
        Script => 'v1',
        For => 'Bind,Squid,Shorewall',
        Local => "$Temp_Path/hosts2.txt",
    });

push ( @{$databases}, {
        Title => 'spyeye',
        Activ => 1,
        URL => 'http://www.abuse.ch/spyeyetracker/blocklist.php?download=domainblocklist',
        Category => 'Abuse.ch/SpyEye',
        Script => 'v1',
        For => 'Bind,Squid,Shorewall',
        Local => "$Temp_Path/hosts3.txt",
    });

push ( @{$databases}, {
        Title => 'zeus',
        Activ => 1,
        URL => 'http://www.abuse.ch/zeustracker/blocklist.php?download=domainblocklist',
        Category => 'Abuse.ch/Zeus',
        Script => 'v1',
        For => 'Bind,Squid,Shorewall',
        Local => "$Temp_Path/hosts4.txt",
    });

push ( @{$databases}, {
        Title => 'amada',
        Activ => 1,
        URL => 'http://amada.abuse.ch/blocklist.php?download=domainblocklist',
        Category => 'Abuse.ch/Amada',
        Script => 'v1',
        For => 'Bind,Squid,Shorewall',
        Local => "$Temp_Path/hosts5.txt",
    });

push ( @{$databases}, {
        Title => 'shallalist',
        Activ => 1,
        URL => 'http://www.shallalist.de/Downloads/shallalist.tar.gz',
        MD5 => 'http://www.shallalist.de/Downloads/shallalist.tar.gz.md5',
        Category => 'Shallalist',
        Extract_Category => 'adv,aggressive,anonvpn,costtraps,remotecontrol,spyware,tracker',
        Script => 'v1',
        For => 'Bind,Squid,Shorewall',
        Local => "$Temp_Path/shallalist.tar.gz",
    });

push ( @{$databases}, {
        Title => 'IWF',
        Activ => 0,
        URL => 'http://',
        Category => 'IWF',
        Script => 'v4',
        For => 'Bind,Squid,Shorewall',
        Local => "$Temp_Path/hosts7.txt",
    });

# http://squidguard.mesd.k12.or.us/blacklists.tgz
# http://cri.univ-tlse1.fr/documentations/cache/squidguard_en.html#contrib
# http://doc.pfsense.org/index.php/SquidGuard_package
# Websense - download.websense.com
# SmartFilter - list.smartfilter.com

=head1 

END of Configuration

=cut

my $blacklist='';
my $Fileout;
my $Blacklist_tmp_Domain = '';
my $Blacklist_Domain = ();
my $dom = {};

sub rec1 ($$$$) {
    my ( $subdom, $empty, $i, $hash ) = @_;

    if ( $i < 0 ) {
        $hash = 'END';
        return $hash;
    }
    print "$i ". $subdom->[$i] . "\n" if $verbose;
    $i--;
    if ( defined($hash->{ $subdom->[$i+1] }) && ( $hash->{ $subdom->[$i+1] } eq 'END' ) && ( $empty != $i ) ) {
        print "Exiting loop ". Dumper($subdom) . ", $empty, $i, " . Dumper($hash) if $debug;
        return $hash;
    } else {
        $hash->{ $subdom->[$i+1] } = &rec1 ( $subdom, $empty, $i, $hash->{ $subdom->[$i+1] } );
    }
    print "L:".($i+1).":".Dumper ( $hash ) if $verbose;
    print "-=-=-=-=-=-\n" if $verbose;
    return $hash;
}

sub generate_tree ($$$)
{
    my ( $Blacklist_Domain, $Blacklist_1_Domain, $debug ) = @_;
    foreach my $d ( split ('\n', $Blacklist_1_Domain ) ) {
        next if ( $d =~/^\s*$/ );
        $d =~s/#.*$//g;
        $d =~s/^127.0.0.1\s*//g;
        $d =~s/^::1\s*//g;
        $d =~s/\s*$//g;
        next if ( $d eq 'localhost' );
        print "-->".$d . "\n" if $verbose;
        my @tmp = split(/\./, $d );
        print Dumper (\@tmp) if $debug;

        $Blacklist_Domain = &rec1 ( \@tmp, $#tmp, $#tmp, $Blacklist_Domain );

        print "Final:" . Dumper ( $Blacklist_Domain ) if $debug;
    }

    return $Blacklist_Domain;
}

sub generate_file ($$$$)
{
    my ($Blacklist_Domain, $suffix, $file_out, $level ) = @_;

    my $current_suffix = '';
    foreach my $d1 (sort keys %$Blacklist_Domain ) {
        if ( $level == 0 ) {
            $suffix = '';
        }
        if ( $Blacklist_Domain->{$d1} =~ /HASH\(/ ) {
            generate_file ( $Blacklist_Domain->{$d1}, "$d1.$suffix", $file_out, $level+1 );
        } else {
            $suffix =~s/\.$//;
            print $file_out "zone \"$d1.$suffix\" { type master; notify no; file \"$Bind_Env/blockeddomain.hosts\"; };\n";
        }
    }
}

sub generate_block_file ($)
{
    my ( $blockeddomain_file ) = @_;

=head2

Get/Set current serial
This is in theory not needed, but it's fun isn't it?

=cut

    my $serial = '';

    my $dt = DateTime->now()->set_time_zone("Europe/Luxembourg");
    my $date = $dt->ymd('');

    if ( -f $blockeddomain_file ) {
        $serial = `grep "serial number" $blockeddomain_file | sed 's/;.*\$//' | sed 's/ //g'`;
        chomp ( $serial );
        metaprint 'info', "Current serial is '$serial'";

        if ( $serial =~/^(\d{4}\d{2}\d{2})(\d{2})$/ ) {
            if ( $1 eq $date ) {
                if ( $2 < 9 ) {
                    $serial = $date.'0'.($2+1);
                } else {
                    $serial = $date.($2+1);
                }
            } else {
                $serial = $date.'01';
            }
        } else {
            $serial = $date.'01';
        }
    } else {
        $serial = $date.'01';
    }

    metaprint 'info', "New Serial is '$serial'";

=head2

Writeout the BIND db file with proper content 

=cut

    my $fileout;
    open ( $fileout, ">$blockeddomain_file");

    print $fileout <<OUT;
;
; BIND db file for bad stuff 
;     There's is no place like 127.0.0.1
;
\$TTL    86400   ; one day
;
@       IN      SOA     localhost. root.localhost. (
                $serial  ; serial number YYMMDDNN
                28800       ; refresh  8 hours
                7200        ; retry    2 hours
                864000      ; expire  10 days
                86400 )     ; min ttl  1 day
;
		NS   localhost.
                A    127.0.0.1
                AAAA ::1

*               IN      A       127.0.0.1
*               IN	AAAA	::1
OUT

    close $fileout;
}

sub Get_HTTP_File ($$$$)
{
    my ( $ua, $url, $title, $local ) = @_;

    my $local_version = 0;
    my $req = HTTP::Request->new( GET => $url );
    my $req_http = $ua->request($req);

    if ($req_http->is_success) {
        if ($req_http->code != 200 ) {
            metaprint 'critic', "Game-Over... Response code : " . $req_http->code;
            metaprint 'critic', "Status: " . $req_http->status_line;
            metaprint 'critic', "Did not sucessfully get the File $title.\n";
            if ( -f $local  ) {
                $local_version = 1;
            } else {
                return (-1, undef);
            }
        }
    } else {
        metaprint 'critic', "Game-Over... Response code : " . $req_http->code;
        metaprint 'critic', "Status: " . $req_http->status_line;
        metaprint 'critic', "Did not sucessfully get the File $title.\n";
        if ( -f $local ) {
            $local_version = 1;
        } else {
            return (-1, undef);
        }
    }

    return ( $local_version, $req_http );
}

sub Dump_to_disk ($$)
{
    my ( $database, $file ) = @_;

    my $Blacklist_tmp_Domain = '';

    if ( ( !defined($database->{'Script'}) ) || ( $database->{'Script'} =~/^\s*$/ ) ) {
        next;
    } elsif ( $database->{'Script'} eq 'v1' ) {

        my $cmd = "grep -v '^#' $file | grep -v -e '^\$' | grep -v '^localhost\$' | awk -F. '{ print NF,\$ARGIND }' | sort -n | awk '{ print \$2 }' | uniq";
        $Blacklist_tmp_Domain = `$cmd`;

    } elsif ( $database->{'Script'} eq 'v2' ) {

        my $cmd = "grep '^zone ' $file | awk '{ print \$2 }' | sed 's/\"//g' | grep -v -e '^\$' | awk -F. '{ print NF,\$ARGIND }' | sort -n | awk '{ print \$2 }' | grep -v -e '^\$' | grep -v '^localhost\$' | uniq";
        $Blacklist_tmp_Domain = `$cmd`;

    }
    return $Blacklist_tmp_Domain;
}

sub Check_Directory ($)
{
    my ($directory) = @_;

    if(! -d $directory ) {
        if ( !mkdir $directory ) {
            if ( 0 != system("mkdir -p $directory") ) {
                metaprint 'critic', "Cannot create directory '$directory'.";
            }
        }
        return 0;
    } else {
        return 0;
    }
}

if ( -f $Blacklist_tmp_file ) {
    system("rm -f $Blacklist_tmp_file");
}

my $fromcache = 0;

# TODO: move user-agent to header...
my $ua = LWP::UserAgent->new(agent => 'Mozilla/4.73 [en] (X11; I; Linux 2.2.16 i686; Nav)' );
if ( defined($http_proxy) && ( $http_proxy !~ /^\s*$/ ) ) {
    $ua->proxy('http', $http_proxy );
}
$ua->timeout(10);

my $local_version = 0;
foreach my $database ( @{$databases} ) {
    next if ( !$database->{'Activ'} );
    $local_version = 0;
    metaprint 'info', "Running Blacklist " . $database->{'Title'};

    $fromcache = 0;
    if ( ( -f $database->{'Local'} ) && ( -w $database->{'Local'} ) ) {
        my (
            $dev,  $ino,   $mode,  $nlink, $uid,     $gid, $rdev,
            $size, $atime, $mtime, $ctime, $blksize, $blocks
          ) = stat ( $database->{'Local'} );

        $ctime = 0 if ( !defined($ctime) );

        my $timecache = time() - $ctime;
        if ( $timecache < 86400 ) {
            $fromcache = 1;
        }
    } else {
        $fromcache = 0;
    }

    my $req_http;
    my $req_http_md5;
    my $content = '';
    if ( $fromcache != 1 ) {
        ($local_version, $req_http) = Get_HTTP_File ( $ua, $database->{'URL'}, $database->{'Title'}, $database->{'Local'} );

        if ( $local_version == -1 ) {
            metaprint 'critic', "Did not sucessfully get the File " . $database->{'Title'} . ". Skip.";
            next;
        } elsif ( $local_version == 0 ) {
            $content = $req_http->content();
        }
        if ( ( $local_version == 0 ) && ( defined($database->{'MD5'}) ) ) {
            my $local_md5 = '';
            ($local_md5, $req_http_md5) = Get_HTTP_File ( $ua, $database->{'MD5'}, $database->{'Title'}, $database->{'Local'}.".md5" );
            if ( $local_version == -1 ) {
                metaprint 'critic', "Did not sucessfully get the MD5 File " . $database->{'Title'} . ". Skip\n";
                next;
            }

            my $content_md5 = $req_http_md5->content();
            my $md5_file = basename ( $database->{'URL'} );

            foreach my $l ( split ('\n', $content_md5 ) ) {
                chomp ( $l );
                $l =~s/\r*//g;
                if ( $l =~ /^([0-9a-f]+)\s+([\w\.]+)$/ ) {
                    if ( $2 eq $md5_file ) {
                        $content_md5 = $1;
                        $content_md5 =~s/^\s*//;
                        $content_md5 =~s/\s.*$//g;
                        last;
                    }
                }
            }

            # checking the MD5
            my $ctx = Digest::MD5->new;

            $ctx->add($content);
            my $digest = $ctx->hexdigest;

            # $digest $database->{'Local'}
            if ( $content_md5 ne $digest ) {
                metaprint 'critic', "MD5 is not matching for '$md5_file', skipping:";
                print "'$content_md5'\n";
                print "'$digest'\n";
                next;
            } else {
                metaprint 'info', "MD5 is ok.";
            }
        }

    } else {
        $local_version = 1;
        metaprint 'info', "Using local version.";
    }

    if ( ( $local_version == 0 ) && ( $database->{'Local'} =~/\.gz$/ ) ) {

        open ( $Fileout, '>'.$database->{'Local'} );
        print $Fileout $content."\n";
        close $Fileout;

    }

    my $to_extract = ();

    if ( $database->{'Local'} =~/\.gz$/ ) {

        my $tar = Archive::Tar->new( $database->{'Local'} );
        if ( !defined($tar) ) {
            metaprint 'critic', "Extract of TAR content failed for " . $database->{'Title'} . ", skipped...";
            next;
        }

        my $tar_files;
        @$tar_files = $tar->list_files( ['name'] );

        if (!defined( $database->{'Extract_Category'} ) ) {
            metaprint 'critic', "The 'Extract_Category' need to be defined.";
            next;
        }

        my $tar_ext;
        @$tar_ext = split ( ',', $database->{'Extract_Category'} );

        Check_Directory ( $Temp_Path . '/' . $database->{'Title'} );

        # BL/gamble/domains
        foreach my $file ( @$tar_files ) {
            foreach my $ext ( @$tar_ext ) {
                if ( $file eq 'BL/'.$ext.'/domains' ) {
                    Check_Directory ( $Temp_Path . '/' . $database->{'Title'} . '/' . $ext );
                    $tar->extract_file( $file, $Temp_Path . '/' . $database->{'Title'} . '/' . $ext . '/domains' );
                    push ( @$to_extract, $Temp_Path . '/' . $database->{'Title'} . '/' . $ext . '/domains' );
                }
            }
        }

    } elsif ( $local_version == 0 ) {

        $content =~ s/^\#.*$//mg;
        $content =~ s/^\s*$//mg;
        $content =~ s/^\s*\n+//mg;

        $content =~ s/\s\#.*$//mg;
        $content =~ s/^/\t/mg;
        $content =~ s/\s+$//mg;
        $content =~ s/^\s+//mg;

        $content =~ s/\r//g;
        $content =~ s/^127.0.0.1\s+//mg;
        $content =~ s/^::1\s+//mg;
        $content =~ s/^localhost$//mg;
        $content =~ s/^\s*\n+//mg;

        $content = lc( $content );

        open ( $Fileout, '>'.$database->{'Local'} );
        print $Fileout $content."\n";
        close $Fileout;

        push ( @$to_extract, $database->{'Local'} );
    } elsif ( $local_version == 1 ) {
        push ( @$to_extract, $database->{'Local'} );
    }

    #foreach my $str ( $content )
    # $n = () = $str =~ /\./g;
    # print $n;
    #}

    print Dumper ( $to_extract ); # if $verbose;

    $Blacklist_tmp_Domain = '';
    foreach my $file_to_process ( @$to_extract ) {
        $Blacklist_tmp_Domain .= Dump_to_disk ( $database, $file_to_process );
        $Blacklist_tmp_Domain .= "\n";

        my $nb_of_lines = $Blacklist_tmp_Domain =~ tr/\n//;
        metaprint 'info', "Cummulative number of lines for this Blacklist in '$file_to_process' is '$nb_of_lines'";
    }

    if ( $Blacklist_tmp_Domain !~/^\s*$/ ) {
        open ( $Fileout, ">>$Blacklist_tmp_file" );
        print $Fileout $Blacklist_tmp_Domain."\n";
        close $Fileout;
    } else {
        metaprint 'Warn', "Suspicious: The output of the processing is empty!";
    }
}

metaprint 'info', "MASTER processing...";

#IPv4=^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$
#IPV6='(^([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}){1})|::'

# Bind cannot have IP in the blacklist...

metaprint 'info', "generating Bind_Blacklist_tmp_Domain";
my $Bind_Blacklist_tmp_Domain = `grep -v '^localhost\$' $Blacklist_tmp_file | grep -v -e '^\$' | tr [A-Z] [a-z] | awk -F. '{ print NF,\$ARGIND }' | sort -n | awk '{ print \$2 }' | uniq | egrep -v "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\$" `;

metaprint 'info', "generating Blacklist_tmp_Domain";
$Blacklist_tmp_Domain = `grep -v '^localhost\$' $Blacklist_tmp_file | grep -v -e '^\$' | tr [A-Z] [a-z] | awk -F. '{ print NF,\$ARGIND }' | sort -n | awk '{ print \$2 }' | uniq `;

# print Dumper $Blacklist_tmp_Domain;

# Bind Stuff

metaprint 'info', "generating listing";
$Blacklist_Domain = generate_tree ( $Blacklist_Domain, $Bind_Blacklist_tmp_Domain, $debug );

# print Dumper ( $Blacklist_Domain );

open ( $Fileout, ">$Bind_zone_new");
generate_file ( $Blacklist_Domain, '', $Fileout, 0 );
close $Fileout;

## -- Move tmp file to real one
my $newsize = 0;
$newsize = -s $Bind_zone_new if (-e $Bind_zone_new);

#
my $cursize = 0;
$cursize = -s $Bind_zone_prod if (-e $Bind_zone_prod);

#
my $pctsize = 0;
$pctsize = (($newsize - $cursize)/$cursize)*100 if $cursize > 0;

#
if ($newsize > 0 && $pctsize > -25) {
    if ( $pctsize > 25) {
        metaprint 'Warn', "BlackList generated contains more than 25% growth... please check ASAP!";
    }
    move ($Bind_zone_prod, $Bind_zone_prod_old);

    if (move ($Bind_zone_new, $Bind_zone_prod)) {
        metaprint 'info', "Bind BlackList generated/updated correctly.";
    } else {
        metaprint 'critic', "Move of New BlackList in production failed: $!";
        move ($Bind_zone_prod_old, $Bind_zone_prod);
    }
} else {
    metaprint 'critic', "More than 25% of rows removed on the black_list, problem suspected.";
    metaprint 'critic', "Process aborted.";
    exit(1);
}

generate_block_file ( $Bind_block_file );

# end of BIND process.

exit 0;

