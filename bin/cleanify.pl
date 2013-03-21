#!/usr/bin/perl

BEGIN {
    $ENV{'BASH_ENV'}    = '';
    $ENV{'ENV'}         = '';
    $ENV{'LC_COLLATE'}  = 'C';
    $ENV{'LC_CTYPE'}    = 'C';
    $ENV{'LC_MESSAGES'} = 'C';
    $ENV{'LC_MONETARY'} = 'C';
    $ENV{'LC_NUMERIC'}  = 'C';
    $ENV{'LC_TIME'}     = 'C';
    $ENV{'LC_ALL'}      = 'C';
}

use strict;
use warnings;
use Data::Dumper;
use DateTime;
use LWP::UserAgent;
use Digest::MD5;
use Archive::Tar;
use File::Copy;
use Date::Format( 'time2str' );
use File::Basename;
use Config::IniFiles;
use File::Spec;

my $debug   = 0;
my $verbose = 0;

sub metaprint ($$);
sub db_val_load ($$$);
sub load_list ($);
sub rec1 ($$$$);
sub generate_tree ($$$$);
sub generate_bind_zone_file ($$$$);
sub generate_block_file ($);
sub Get_HTTP_File ($$$$);
sub Bind_Dump_to_disk ($$);
sub Check_Directory ($);

sub metaprint ($$)
{
    my ( $level, $display ) = @_;

    print time2str( "%T", time() ) . " - ["
      . uc( $level ) . "] - "
      . ( ( caller( 1 ) )[3] ? ( caller( 1 ) )[3] : '' ) . " - "
      . ( ( caller( 0 ) )[2] ? 'L' . ( caller( 0 ) )[2] . ' - ' : '' )
      . $display . "\n";
}

my $abs_path = dirname( File::Spec->rel2abs( $0 ) );
print "Current script path is: '$abs_path'\n";

=head1

Load parameters from the ini files.

=cut

my $ini = "$abs_path/../ini/global.ini";
if ( ( !-f $ini ) && ( !-r $ini ) ) {
    metaprint 'critic', "The ini file is not found or not readable, aborting.";
    exit 1;
}

my $cfg = Config::IniFiles->new( -file => $ini );

my $Temp_Path = $cfg->val( 'global', 'resources_path' );
$Temp_Path = '/tmp/' if ( !defined( $Temp_Path ) || ( $Temp_Path =~ /^\s*$/ ) );

my $http_proxy = $cfg->val( 'global', 'http_proxy' );

my $Bind_Env = $cfg->val( 'global', 'bind_path' );
if ( !defined( $Bind_Env ) || ( $Bind_Env =~ /^\s*$/ ) ) {
    metaprint 'critic', "The Bind path is empty.";
    exit 1;
} elsif ( !-d $Bind_Env ) {
    metaprint 'critic', "The Bind path doesnot exist.";
    exit 1;
}
my $user_agent = $cfg->val( 'global', 'UA' );
$user_agent = 'Mozilla/4.73 [en] (X11; I; Linux 2.2.16 i686; Nav)' if ( !defined( $user_agent ) || ( $user_agent =~ /^\s*$/ ) );

my $SquidGuard_db_Env = $cfg->val( 'global', 'squid_db_path' );
if ( !defined( $SquidGuard_db_Env ) || ( $SquidGuard_db_Env =~ /^\s*$/ ) ) {
    metaprint 'critic', "The SquidGuard_db_Env is not defined. So exiting!";
    exit 1;
}
my $ip4_redirector = $cfg->val( 'global', 'ip4_redirector' );
if ( !defined( $ip4_redirector ) || ( $ip4_redirector !~ // ) ) {
    metaprint 'critic', "The ip4_redirector values is not correct, assuming '127.0.0.1'";
    $ip4_redirector = '127.0.0.1';
}
my $ip6_redirector = $cfg->val( 'global', 'ip6_redirector' );
if ( !defined( $ip6_redirector ) || ( $ip6_redirector !~ // ) ) {
    metaprint 'critic', "The ip6_redirector values is not correct, assuming '::1'";
    $ip6_redirector = '::1';
}

my $rbldns_ip = $cfg->val( 'global', 'rbldns_ip' );
if ( !defined( $rbldns_ip ) || ( $rbldns_ip !~ // ) ) {
    metaprint 'critic', "The rbldns_ip values is not correct, no assumption, so exiting!";
    exit 1;
}

my $ddl_path = "$Temp_Path/ddl";
Check_Directory( $ddl_path );

my $tmp_path = "$Temp_Path/tmp";
Check_Directory( $tmp_path );

my $Bind_zone_prod     = "$Temp_Path/named.conf.block";
my $Bind_zone_prod_old = "$Temp_Path/named.conf.block.old";
my $Bind_zone_new      = "$Temp_Path/named.conf.block.new";
my $Bind_block_file    = "$Temp_Path/blockeddomain.hosts";

my $SquidGuard_conf_file = "$Temp_Path/squidGuard.conf";

my $Rbldns_conf_file_prod = "$Temp_Path/rbldns_bad_guys";
my $Rbldns_conf_file_old  = "$Temp_Path/rbldns_bad_guys.old";
my $Rbldns_conf_file_new  = "$Temp_Path/rbldns_bad_guys.new";

my $nginx_conf_file_prod = "$Temp_Path/nginx_blockips";
my $nginx_conf_file_old  = "$Temp_Path/nginx_blockips.old";
my $nginx_conf_file_new  = "$Temp_Path/nginx_blockips.new";

my $Blacklist_tmp_bind_file      = "$Temp_Path/result_tmp_bind";
my $Blacklist_tmp_shorewall_file = "$Temp_Path/result_tmp_shorewall";
my $Blacklist_tmp_rbldns_file    = "$Temp_Path/result_tmp_rbldns";
my $Blacklist_tmp_nginx_file     = "$Temp_Path/result_tmp_nginx";

my $white_file = "$abs_path/" . $cfg->val( 'global', 'whitelist' );
if ( ( !-f $white_file ) && ( !-r $white_file ) ) {
    metaprint 'critic', "Whitelist file is not found or not readable, aborting";
    exit 1;
}

my $databases = [];

=head1

  Load the ini file with the Database to be used.

=cut

my $dbf = "$abs_path/../ini/database.ini";
if ( ( !-f $dbf ) && ( !-r $dbf ) ) {
    metaprint 'critic', "The db file is not found or not readable, aborting.";
    exit 1;
}

print "dbf file at '$dbf'\n";
my $dbcfg = Config::IniFiles->new( -file => $dbf );

sub db_val_load ($$$)
{
    my ( $dbcfg, $title, $val ) = @_;
    if ( $dbcfg->exists( $title, $val ) ) {
        return $dbcfg->val( $title, $val );
    } else {
        print "section '$title' value '$val' not found.\n" if ( $val !~ /^(Extract_Category|Tar_Prefix|MD5|Type)$/ );
        return -1;
    }
}

foreach my $db ( $dbcfg->Sections() ) {
    my $tmp = ();

    # Activ
    if ( $dbcfg->exists( $db, 'Activ' ) ) {
        if ( $dbcfg->val( $db, 'Activ' ) ) {
            print "loading parameter for database $db.\n";
            $tmp->{'Activ'} = 1;
        } else {
            next;
        }
    } else {
        print "skipping loading of database $db, value 'Activ' not found.\n";
        next;
    }

    $tmp->{'Title'} = $db;

    # URL
    my $temp = db_val_load( $dbcfg, $db, 'URL' );
    if ( defined( $temp ) && ( $temp =~ /^-1$/ ) ) {
        metaprint 'critic', "Val of 'URL' for '$db' not found, skipping.";
        next;
    }
    if ( defined( $temp ) && ( $temp !~ /^\s*$/ ) ) {
        $tmp->{'URL'} = $temp;
    } else {
        metaprint 'critic', "Val of 'URL' for '$db' not conform, , skipping.";
        next;
    }

    # MD5
    $temp = db_val_load( $dbcfg, $db, 'MD5' );
    if ( defined( $temp ) && ( $temp !~ /^\s*$/ ) && ( $temp !~ /^-1$/ ) ) {
        $tmp->{'MD5'} = $temp;
    }

    # Category
    $temp = db_val_load( $dbcfg, $db, 'Category' );
    if ( defined( $temp ) && ( $temp =~ /^-1$/ ) ) {
        metaprint 'critic', "Val of 'Category' for '$db' not found, skipping.";
        next;
    }
    if ( defined( $temp ) && ( $temp !~ /^\s*$/ ) ) {
        $tmp->{'Category'} = $temp;
    } else {
        metaprint 'critic', "Val of 'Category' for '$db' not conform, , skipping.";
        next;
    }

    # Extract_Category
    $temp = db_val_load( $dbcfg, $db, 'Extract_Category' );
    if ( defined( $temp ) && ( $temp !~ /^\s*$/ ) && ( $temp !~ /^-1$/ ) ) {
        $tmp->{'Extract_Category'} = $temp;
    }

    # Tar_Prefix
    $temp = db_val_load( $dbcfg, $db, 'Tar_Prefix' );
    if ( defined( $temp ) && ( $temp !~ /^\s*$/ ) && ( $temp !~ /^-1$/ ) ) {
        $tmp->{'Tar_Prefix'} = $temp;
    }

    # Type
    $temp = db_val_load( $dbcfg, $db, 'Type' );
    if ( defined( $temp ) && ( $temp !~ /^\s*$/ ) && ( $temp !~ /^-1$/ ) ) {
        $tmp->{'Type'} = $temp;
    }

    # Script
    $temp = db_val_load( $dbcfg, $db, 'Script' );
    if ( defined( $temp ) && ( $temp =~ /^-1$/ ) ) {
        metaprint 'critic', "Val of 'Script' for '$db' not found, skipping.";
        next;
    }
    if ( defined( $temp ) && ( $temp !~ /^\s*$/ ) ) {
        $tmp->{'Script'} = $temp;
    } else {
        $tmp->{'Script'} = '';
    }

    # For
    $temp = db_val_load( $dbcfg, $db, 'For' );
    if ( defined( $temp ) && ( $temp =~ /^-1$/ ) ) {
        metaprint 'critic', "Val of 'For' for '$db' not found, skipping.";
        next;
    }
    if ( defined( $temp ) && ( $temp !~ /^\s*$/ ) ) {
        $tmp->{'For'} = $temp;
    } else {
        metaprint 'critic', "Val of 'For' for '$db' not conform, , skipping.";
        next;
    }

    # Local
    $temp = db_val_load( $dbcfg, $db, 'Local' );
    if ( defined( $temp ) && ( $temp =~ /^-1$/ ) ) {
        metaprint 'critic', "Val of 'Local' for '$db' not found, skipping.";
        next;
    }
    if ( defined( $temp ) && ( $temp !~ /^\s*$/ ) ) {
        $tmp->{'Local'} = $ddl_path . "/" . $temp;
    } else {
        metaprint 'critic', "Val of 'Local' for '$db' not conform, , skipping.";
        next;
    }

    push( @{$databases}, $tmp );
}

print Dumper ( @{$databases} ) if $debug;

=head1 

END of Configuration

=cut

my $blacklist = '';
my $Fileout;
my $Blacklist_tmp_Domain = '';
my $Blacklist_Domain     = ();
my $Whitelist_Domain     = ();
my $dom                  = {};

sub load_list ($)
{
    my ( $file ) = @_;

    my $list = ();
    my $filein;
    open( $filein, "<$file" );

    while ( my $dmn = <$filein> ) {
        next if ( $dmn =~ /^#/ );
        chomp( $dmn );
        $dmn =~ s/\r+//g;
        $dmn =~ s/#.*$//g;
        $dmn =~ s/\s*//g;
        next if ( $dmn =~ /^\s*$/ );
        my $n = () = $dmn =~ /\./g;

        # print "#dot:" . $n . ":$dmn:" . "\n";
        next if ( $n < 1 );
        push( @$list, $dmn );
    }
    close( $filein );
    return $list;
}

sub rec1 ($$$$)
{
    my ( $subdom, $empty, $i, $hash ) = @_;

    if ( $i < 0 ) {
        $hash = 'END';
        return $hash;
    }
    print "$i " . $subdom->[$i] . "\n" if $verbose;
    $i--;
    if ( defined( $hash->{ $subdom->[ $i + 1 ] } ) && ( $hash->{ $subdom->[ $i + 1 ] } eq 'END' ) && ( $empty != $i ) ) {
        print "Exiting loop " . Dumper( $subdom ) . ", $empty, $i, " . Dumper( $hash ) if $debug;
        return $hash;
    } else {
        $hash->{ $subdom->[ $i + 1 ] } = &rec1( $subdom, $empty, $i, $hash->{ $subdom->[ $i + 1 ] } );
    }
    print "L:" . ( $i + 1 ) . ":" . Dumper( $hash ) if $verbose;
    print "-=-=-=-=-=-\n" if $verbose;
    return $hash;
}

sub generate_tree ($$$$)
{
    my ( $Blacklist_Domain, $Blacklist_1_Domain, $Whitelist_Domain, $debug ) = @_;

    my $wfound = 0;
    foreach my $d ( split( '\n', $Blacklist_1_Domain ) ) {
        next if ( $d =~ /^\s*$/ );
        $d =~ s/#.*$//g;
        $d =~ s/^127.0.0.1\s*//g;
        $d =~ s/^::1\s*//g;
        $d =~ s/\s*$//g;
        next if ( $d eq 'localhost' );
        print "-->" . $d . "\n" if $verbose;

        $wfound = 0;
        if ( defined( $Whitelist_Domain ) ) {
            foreach my $w ( @$Whitelist_Domain ) {

                # if ( ( $d =~ /\.$w$/ ) || ( $d =~ /^$w$/ ) ) {
                if ( $d =~ /^$w$/ ) {
                    print "'$d' is matching '$w' from whitelist.\n" if $debug;
                    $wfound = 1;
                    last;
                }
            }
        }
        if ( $wfound ) {
            metaprint 'info', "'$d' is matching the whitelist, skipping.";
            next;
        }

        my @tmp = split( /\./, $d );
        print Dumper ( \@tmp ) if $debug;

        $Blacklist_Domain = &rec1( \@tmp, $#tmp, $#tmp, $Blacklist_Domain );

        print "Final:" . Dumper( $Blacklist_Domain ) if $debug;
    }

    return $Blacklist_Domain;
}

sub generate_bind_zone_file ($$$$)
{
    my ( $Blacklist_Domain, $suffix, $file_out, $level ) = @_;

    my $current_suffix = '';
    foreach my $d1 ( sort keys %$Blacklist_Domain ) {
        if ( $level == 0 ) {
            $suffix = '';
        }
        if ( $Blacklist_Domain->{$d1} =~ /HASH\(/ ) {
            generate_bind_zone_file( $Blacklist_Domain->{$d1}, "$d1.$suffix", $file_out, $level + 1 );
        } else {
            $suffix =~ s/\.$//;
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

    my $dt   = DateTime->now()->set_time_zone( "Europe/Luxembourg" );
    my $date = $dt->ymd( '' );

    if ( -f $blockeddomain_file ) {
        $serial = `grep "serial number" $blockeddomain_file | sed 's/;.*\$//' | sed 's/ //g'`;
        chomp( $serial );
        metaprint 'info', "Current serial is '$serial'";

        if ( $serial =~ /^(\d{4}\d{2}\d{2})(\d{2})$/ ) {
            if ( $1 eq $date ) {
                if ( $2 < 9 ) {
                    $serial = $date . '0' . ( $2 + 1 );
                } else {
                    $serial = $date . ( $2 + 1 );
                }
            } else {
                $serial = $date . '01';
            }
        } else {
            $serial = $date . '01';
        }
    } else {
        $serial = $date . '01';
    }

    metaprint 'info', "New Serial is '$serial'";

=head2

Writeout the BIND db file with proper content 

=cut

    my $fileout;
    open( $fileout, ">$blockeddomain_file" );

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
                A    $ip4_redirector
                AAAA $ip6_redirector

*               IN      A       $ip4_redirector
*               IN	AAAA	$ip6_redirector
OUT

    close $fileout;
}

sub Get_HTTP_File ($$$$)
{
    my ( $ua, $url, $title, $local ) = @_;

    my $local_version = 0;
    my $req           = HTTP::Request->new( GET => $url );
    my $req_http      = $ua->request( $req );

    if ( $req_http->is_success ) {
        if ( $req_http->code != 200 ) {
            metaprint 'critic', "Game-Over... Response code : " . $req_http->code;
            metaprint 'critic', "Status: " . $req_http->status_line;
            metaprint 'critic', "Did not sucessfully get the File $title.\n";
            if ( -f $local ) {
                $local_version = 1;
            } else {
                return ( -1, undef );
            }
        }
    } else {
        metaprint 'critic', "Game-Over... Response code : " . $req_http->code;
        metaprint 'critic', "Status: " . $req_http->status_line;
        metaprint 'critic', "Did not sucessfully get the File $title.\n";
        if ( -f $local ) {
            $local_version = 1;
        } else {
            return ( -1, undef );
        }
    }

    return ( $local_version, $req_http );
}

sub Bind_Dump_to_disk ($$)
{
    my ( $database, $file ) = @_;

    my $Blacklist_tmp_Domain = '';

    if ( ( !defined( $database->{'Script'} ) ) || ( $database->{'Script'} =~ /^\s*$/ ) ) {
        return '';
    } elsif ( $database->{'Script'} eq 'v1' ) {
        my $cmd = "grep -v '^#' $file | grep -v -e '^\$' | grep -v '^localhost\$' | awk -F. '{ print NF,\$ARGIND }' | sort -n | awk '{ print \$2 }' | uniq";
        $Blacklist_tmp_Domain = `$cmd`;
    } elsif ( $database->{'Script'} eq 'v2' ) {
        my $cmd = "grep -v '^#' $file | grep -v -e '^\$' | grep -v '^localhost\$' | sed -e 's/\\\././g' -e 's/^\.//' | awk -F. '{ print NF,\$ARGIND }' | sort -n | awk '{ print \$2 }' | uniq";
        $Blacklist_tmp_Domain = `$cmd`;
    } elsif ( $database->{'Script'} eq 'v3' ) {
        my $cmd = "grep -v '^;' $file | sed 's/ ; .*\$//g' | grep -v -e '^\$' | grep -v '^localhost\$' | grep -v '^127\.0\.0\.' ";

        # metaprint 'info', "Running command: '$cmd'";
        $Blacklist_tmp_Domain = `$cmd`;
    }
    return $Blacklist_tmp_Domain;
}

sub Check_Directory ($)
{
    my ( $directory ) = @_;

    if ( !-d $directory ) {
        if ( !mkdir $directory ) {
            if ( 0 != system( "mkdir -p $directory" ) ) {
                metaprint 'critic', "Cannot create directory '$directory'.";
            }
        }
        return 0;
    } else {
        return 0;
    }
}

=head1

 Main

=cut

=head2

Removing the previous Bind temp file

=cut

if ( -f $Blacklist_tmp_bind_file ) {
    system( "rm -f $Blacklist_tmp_bind_file" );
}

=head2

Removing the previous Squid generating directory

=cut

if ( -d $Temp_Path . '/cleanify/' ) {
    system( "rm -rf $Temp_Path/cleanify" );
}

=head2

Removing the previous Shorewall temp file

=cut

if ( -f $Blacklist_tmp_shorewall_file ) {
    system( "rm -f $Blacklist_tmp_shorewall_file" );
}

=head2

Removing the previous RBLdns temp file

=cut

if ( -f $Blacklist_tmp_rbldns_file ) {
    system( "rm -f $Blacklist_tmp_rbldns_file" );
}

=head2

Removing the previous nginx temp file

=cut

if ( -f $Blacklist_tmp_nginx_file ) {
    system( "rm -f $Blacklist_tmp_nginx_file" );
}

=head2
Loading the Whitelist
=cut

$Whitelist_Domain = load_list( $white_file );
metaprint 'info', "White_List_Domain:" . Dumper( $Whitelist_Domain );

my $fromcache = 0;

=head2
Initialisation of the Web Content fetcher
=cut

my $ua = LWP::UserAgent->new( agent => $user_agent );
if ( defined( $http_proxy ) && ( $http_proxy !~ /^\s*$/ ) ) {
    $ua->proxy( 'http', $http_proxy );
}
$ua->timeout( 10 );

=head2
For each databases defined, process it carrefully...
=cut

metaprint 'info', "Refreshing databases if needed.";

my $squid_cat_to_generate = ();

my $local_version = 0;
foreach my $database ( @{$databases} ) {
    next if ( !$database->{'Activ'} );
    $local_version = 0;
    print "=============\n\n";
    metaprint 'info', "Running Blacklist " . $database->{'Title'};

    # TODO to be moved in the iniFile Database loader.
    $database->{'Category'} = lc( $database->{'Category'} );

    $fromcache = 0;
    if ( ( -f $database->{'Local'} ) && ( -w $database->{'Local'} ) ) {
        my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks ) = stat( $database->{'Local'} );

        $ctime = 0 if ( !defined( $ctime ) );

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
        ( $local_version, $req_http ) = Get_HTTP_File( $ua, $database->{'URL'}, $database->{'Title'}, $database->{'Local'} );

        if ( $local_version == -1 ) {
            metaprint 'critic', "Did not sucessfully get the File " . $database->{'Title'} . ". Skip.";
            next;
        } elsif ( $local_version == 0 ) {
            $content = $req_http->content();
        }
        if ( ( $local_version == 0 ) && ( defined( $database->{'MD5'} ) ) ) {
            my $local_md5 = '';
            ( $local_md5, $req_http_md5 ) = Get_HTTP_File( $ua, $database->{'MD5'}, $database->{'Title'}, $database->{'Local'} . ".md5" );
            if ( $local_version == -1 ) {
                metaprint 'critic', "Did not sucessfully get the MD5 File " . $database->{'Title'} . ". Skip\n";
                next;
            }

            my $content_md5 = $req_http_md5->content();
            my $md5_file    = basename( $database->{'URL'} );

            foreach my $l ( split( '\n', $content_md5 ) ) {
                chomp( $l );
                $l =~ s/\r*//g;
                if ( $l =~ /^([0-9a-f]+)\s+([\w\\:\-\.]+)$/ ) {
                    $content_md5 = $1;
                    my $tmp_file = basename( $2 );
                    $tmp_file =~ s/^.*\\//;
                    if ( $tmp_file eq $md5_file ) {
                        $content_md5 =~ s/^\s*//;
                        $content_md5 =~ s/\s.*$//g;
                        last;
                    }
                } elsif ( $l =~ /^"\d{4}-\d{2}-\d{2}","([0-9a-f]+)","\d+"$/ ) {
                    $content_md5 = $1;
                    last;
                }

            }

            # checking the MD5
            my $ctx = Digest::MD5->new;

            $ctx->add( $content );
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

    if ( ( $local_version == 0 ) && ( $database->{'Local'} =~ /\.gz$/ ) ) {

        open( $Fileout, '>' . $database->{'Local'} );
        print $Fileout $content . "\n";
        close $Fileout;

    }

    my $to_extract_for_bind      = ();
    my $to_extract_for_squid     = ();
    my $to_extract_for_shorewall = ();
    my $to_extract_for_rbldns    = ();
    my $to_extract_for_nginx     = ();

    if ( $database->{'Local'} =~ /\.tar\.gz$/ ) {

        my $tar = Archive::Tar->new( $database->{'Local'} );
        if ( !defined( $tar ) ) {
            metaprint 'critic', "Extract of TAR content failed for " . $database->{'Title'} . ", skipped...";
            next;
        }

        my $tar_files;
        @$tar_files = $tar->list_files( ['name'] );

        if ( !defined( $database->{'Extract_Category'} ) ) {
            metaprint 'critic', "The 'Extract_Category' need to be defined.";
            next;
        }

        my $tar_ext;
        @$tar_ext = split( ',', $database->{'Extract_Category'} );

        Check_Directory( $tmp_path . '/' . $database->{'Title'} );

        # BL/category/domains or BL/category/urls
        foreach my $file ( @$tar_files ) {
            foreach my $ext ( @$tar_ext ) {
                if ( $file eq $database->{'Tar_Prefix'} . '/' . $ext . '/domains' ) {
                    Check_Directory( $tmp_path . '/' . $database->{'Title'} . '/' . $ext );
                    $tar->extract_file( $file, $tmp_path . '/' . $database->{'Title'} . '/' . $ext . '/domains' );
                    if ( $database->{'For'} =~ /Bind/i ) {
                        push( @$to_extract_for_bind, $tmp_path . '/' . $database->{'Title'} . '/' . $ext . '/domains' );
                    }
                    if ( $database->{'For'} =~ /Squid/i ) {
                        push( @$to_extract_for_squid, $tmp_path . '/' . $database->{'Title'} . '/' . $ext . '/domains' );
                    }
                    if ( $database->{'For'} =~ /Shorewall/i ) {
                        push( @$to_extract_for_shorewall, $tmp_path . '/' . $database->{'Title'} . '/' . $ext . '/domains' );
                    }
                    if ( $database->{'For'} =~ /RBLdns/i ) {
                        push( @$to_extract_for_rbldns, $tmp_path . '/' . $database->{'Title'} . '/' . $ext . '/domains' );
                    }
                    if ( $database->{'For'} =~ /nginx/i ) {
                        push( @$to_extract_for_nginx, $tmp_path . '/' . $database->{'Title'} . '/' . $ext . '/domains' );
                    }
                } elsif ( $file eq $database->{'Tar_Prefix'} . '/' . $ext . '/urls' ) {
                    Check_Directory( $tmp_path . '/' . $database->{'Title'} . '/' . $ext );
                    $tar->extract_file( $file, $tmp_path . '/' . $database->{'Title'} . '/' . $ext . '/urls' );
                    if ( $database->{'For'} =~ /Squid/ ) {
                        push( @$to_extract_for_squid, $tmp_path . '/' . $database->{'Title'} . '/' . $ext . '/urls' );
                    }
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

        open( $Fileout, '>' . $database->{'Local'} );
        print $Fileout $content . "\n";
        close $Fileout;
        if ( $database->{'For'} =~ /Bind/i ) {
            push( @$to_extract_for_bind, $database->{'Local'} );
        }
        if ( $database->{'For'} =~ /Squid/i ) {
            push( @$to_extract_for_squid, $database->{'Local'} );
        }
        if ( $database->{'For'} =~ /Shorewall/i ) {
            push( @$to_extract_for_shorewall, $database->{'Local'} );
        }
        if ( $database->{'For'} =~ /RBLdns/i ) {
            push( @$to_extract_for_rbldns, $database->{'Local'} );
        }
        if ( $database->{'For'} =~ /nginx/i ) {
            push( @$to_extract_for_nginx, $database->{'Local'} );
        }
    } elsif ( $local_version == 1 ) {
        if ( $database->{'For'} =~ /Bind/i ) {
            push( @$to_extract_for_bind, $database->{'Local'} );
        }
        if ( $database->{'For'} =~ /Squid/i ) {
            push( @$to_extract_for_squid, $database->{'Local'} );
        }
        if ( $database->{'For'} =~ /Shorewall/i ) {
            push( @$to_extract_for_shorewall, $database->{'Local'} );
        }
        if ( $database->{'For'} =~ /RBLdns/i ) {
            push( @$to_extract_for_rbldns, $database->{'Local'} );
        }
        if ( $database->{'For'} =~ /nginx/i ) {
            push( @$to_extract_for_nginx, $database->{'Local'} );
        }
    }

    #foreach my $str ( $content ) {
    # $n = () = $str =~ /\./g;
    # print $n;
    #}

    if ( $verbose ) {
        print "List to extract for Bind:" . Dumper( $to_extract_for_bind );
        print "List to extract for Squid:" . Dumper( $to_extract_for_squid );
        print "List to extract for Shorewall:" . Dumper( $to_extract_for_shorewall );
        print "List to extract for RBLdns:" . Dumper( $to_extract_for_rbldns );
        print "List to extract for nginx:" . Dumper( $to_extract_for_nginx );
    }

    if ( $database->{'For'} =~ /Bind/i ) {
        $Blacklist_tmp_Domain = '';
        foreach my $file_to_process ( @$to_extract_for_bind ) {
            $Blacklist_tmp_Domain .= Bind_Dump_to_disk( $database, $file_to_process );
            $Blacklist_tmp_Domain .= "\n";

            my $nb_of_lines = $Blacklist_tmp_Domain =~ tr/\n//;
            metaprint 'info', "Cummulative number of lines for this Bind Blacklist in '$file_to_process' is '$nb_of_lines'";
        }

        if ( $Blacklist_tmp_Domain !~ /^\s*$/ ) {
            open( $Fileout, ">>$Blacklist_tmp_bind_file" );
            print $Fileout $Blacklist_tmp_Domain . "\n";
            close $Fileout;
        } else {
            metaprint 'Warn', "Suspicious: The output of Bind processing is empty!";
        }
    }
    if ( $database->{'For'} =~ /Squid/i ) {

        my $squid_dir = $Temp_Path . '/cleanify/' . $database->{'Category'};
        metaprint 'info', "SquidGuard DB dir is $squid_dir" if $verbose;
        Check_Directory( $squid_dir );

        foreach my $file_to_process ( @$to_extract_for_squid ) {
            my $outfile = '';
            if ( ( $file_to_process =~ /\/urls$/ ) || ( $file_to_process =~ /\/domains$/ ) ) {

                # simply copy them to the right place
                my $ext_path = dirname( $file_to_process );
                my $title    = $database->{'Title'};
                $ext_path =~ s/^.*$title\///g;
                $outfile = "$squid_dir/$ext_path/" . basename( $file_to_process );
                Check_Directory( "$squid_dir/$ext_path" );
                system( "cp $file_to_process $outfile" );
                if ( $file_to_process =~ /\/domains$/ ) {
                    $squid_cat_to_generate->{ $database->{'Category'} . "/" . $ext_path }{'domainlist'} = $database->{'Category'} . "/$ext_path/domains";
                } else {
                    $squid_cat_to_generate->{ $database->{'Category'} . "/" . $ext_path }{'urllist'} = $database->{'Category'} . "/$ext_path/urls";
                }

            } else {

                # hum... using Type to dump the file at the right place
                if ( ( !defined( $database->{'Type'} ) ) || ( $database->{'Type'} =~ /^\s*$/ ) ) {
                    metaprint 'critic', "The database type is not defined for " . $database->{'Title'} . ". Skipping...";
                    next;
                }

                $outfile = $squid_dir . "/" . $database->{'Type'};
                if ( $database->{'Type'} eq 'adblock-expressions' ) {
                    $outfile = $squid_dir . "/expressions";
                }

                # TODO: Check if file exist... it should not!

                my $cmd    = '';
                my $output = '';
                if ( $database->{'Type'} eq 'urls' ) {
                    $cmd                                                           = "cat $file_to_process > $outfile ";
                    $output                                                        = `$cmd`;
                    $squid_cat_to_generate->{ $database->{'Category'} }{'urllist'} = $database->{'Category'} . "/urls";

                } elsif ( $database->{'Type'} eq 'domains' ) {
                    $cmd    = "grep -v '^localhost\$' $file_to_process | grep -v -e '^\$' | tr [A-Z] [a-z] | awk -F. '{ print NF,\$ARGIND }' | sort -n | awk '{ print \$2 }' | uniq > $outfile ";
                    $output = `$cmd`;
                    $squid_cat_to_generate->{ $database->{'Category'} }{'domainlist'} = $database->{'Category'} . "/domains";

                } elsif ( $database->{'Type'} eq 'expressions' ) {
                    $cmd                                                                  = "cat $file_to_process > $outfile ";
                    $output                                                               = `$cmd`;
                    $squid_cat_to_generate->{ $database->{'Category'} }{'expressionlist'} = $database->{'Category'} . "/expressions";
                } elsif ( $database->{'Type'} eq 'adblock-expressions' ) {

                    # https://bugs.launchpad.net/ubuntu/+source/squidguard/+bug/316816
                    $cmd =
                      "sed -e '/@@.*/d' -e '/^!.*/d' -e '/^\\\[.*\\\]\$/d' -e 's#http://#^#g' -e 's,[.?=&/|()[],\\\\&,g' -e 's#*#.*#g' -e 's,\\\$.*\$,,g' -e 's/^-/\\\\-/' -e 's/^\+/\\\\+/' -e '/^\\\.\\\*\$/d' -e 's/\\\\\\([0-9]\\)/\\\\\\\\\\1/g' $file_to_process > $outfile";

                    $output = `$cmd`;
                    $squid_cat_to_generate->{ $database->{'Category'} }{'expressionlist'} = $database->{'Category'} . "/expressions";
                }
                if ( $verbose ) {
                    metaprint 'info', "cmd:$cmd";
                    metaprint 'info', "output:$output";
                }
            }
        }
    }
    if ( $database->{'For'} =~ /Shorewall/i ) {
        $Blacklist_tmp_Domain = '';
        foreach my $file_to_process ( @$to_extract_for_shorewall ) {
            $Blacklist_tmp_Domain .= Bind_Dump_to_disk( $database, $file_to_process );
            $Blacklist_tmp_Domain .= "\n";

            my $nb_of_lines = $Blacklist_tmp_Domain =~ tr/\n//;
            metaprint 'info', "Cummulative number of lines for this Shorewall Blacklist in '$file_to_process' is '$nb_of_lines'";
        }

        if ( $Blacklist_tmp_Domain !~ /^\s*$/ ) {
            open( $Fileout, ">>$Blacklist_tmp_shorewall_file" );
            print $Fileout $Blacklist_tmp_Domain . "\n";
            close $Fileout;
        } else {
            metaprint 'Warn', "Suspicious: The output of shorewall processing is empty!";
        }
    }
    if ( $database->{'For'} =~ /RBLdns/i ) {
        $Blacklist_tmp_Domain = '';
        foreach my $file_to_process ( @$to_extract_for_rbldns ) {
            $Blacklist_tmp_Domain .= Bind_Dump_to_disk( $database, $file_to_process );
            $Blacklist_tmp_Domain .= "\n";

            my $nb_of_lines = $Blacklist_tmp_Domain =~ tr/\n//;
            metaprint 'info', "Cummulative number of lines for this RBLdns Blacklist in '$file_to_process' is '$nb_of_lines'";
        }

        if ( $Blacklist_tmp_Domain !~ /^\s*$/ ) {
            open( $Fileout, ">>$Blacklist_tmp_rbldns_file" );
            print $Fileout $Blacklist_tmp_Domain . "\n";
            close $Fileout;
        } else {
            metaprint 'Warn', "Suspicious: The output of RBLdns processing is empty!";
        }
    }
    if ( $database->{'For'} =~ /nginx/i ) {
        $Blacklist_tmp_Domain = '';
        foreach my $file_to_process ( @$to_extract_for_nginx ) {
            $Blacklist_tmp_Domain .= Bind_Dump_to_disk( $database, $file_to_process );
            $Blacklist_tmp_Domain .= "\n";

            my $nb_of_lines = $Blacklist_tmp_Domain =~ tr/\n//;
            metaprint 'info', "Cummulative number of lines for this nginx Blacklist in '$file_to_process' is '$nb_of_lines'";
        }

        if ( $Blacklist_tmp_Domain !~ /^\s*$/ ) {
            open( $Fileout, ">>$Blacklist_tmp_nginx_file" );
            print $Fileout $Blacklist_tmp_Domain . "\n";
            close $Fileout;
        } else {
            metaprint 'Warn', "Suspicious: The output of nginx processing is empty!";
        }
    }
}

print "=============\n\n";

metaprint 'info', "MASTER processing...";

=head1

Now generating the Master Bind blocking list

=cut

#IPv4=^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$
#IPV6='(^([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}){1})|::'

# Bind cannot have IP in the blacklist...

metaprint 'info', "generating Bind_Blacklist_tmp_Domain";
my $Bind_Blacklist_tmp_Domain =
  `grep -v '^localhost\$' $Blacklist_tmp_bind_file | grep -v -e '^\$' | tr [A-Z] [a-z] | awk -F. '{ print NF,\$ARGIND }' | sort -n | awk '{ print \$2 }' | uniq | egrep -v "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\$" `;

# print Dumper $Blacklist_tmp_Domain;

# Bind Stuff

metaprint 'info', "generating listing";
$Blacklist_Domain = generate_tree( $Blacklist_Domain, $Bind_Blacklist_tmp_Domain, $Whitelist_Domain, $debug );

# print Dumper ( $Blacklist_Domain );

open( $Fileout, ">$Bind_zone_new" );
generate_bind_zone_file( $Blacklist_Domain, '', $Fileout, 0 );
close $Fileout;

## -- Move tmp file to real one
my $newsize = 0;
$newsize = -s $Bind_zone_new if ( -e $Bind_zone_new );

#
my $cursize = 0;
$cursize = -s $Bind_zone_prod if ( -e $Bind_zone_prod );

#
my $pctsize = 0;
$pctsize = ( ( $newsize - $cursize ) / $cursize ) * 100 if $cursize > 0;

#
if ( $newsize > 0 && $pctsize > -25 ) {
    if ( $pctsize > 25 ) {
        metaprint 'Warn', "Bind BlackList generated contains more than 25% growth... please check ASAP!";
    }
    move( $Bind_zone_prod, $Bind_zone_prod_old );

    if ( move( $Bind_zone_new, $Bind_zone_prod ) ) {
        metaprint 'info', "Bind BlackList generated/updated correctly.";
    } else {
        metaprint 'critic', "Move of New Bind BlackList in production failed: $!";
        move( $Bind_zone_prod_old, $Bind_zone_prod );
    }
} else {
    metaprint 'critic', "More than 25% of rows removed on the Bind black_list, problem suspected.";
    metaprint 'critic', "Process aborted.";
    exit( 1 );
}

generate_block_file( $Bind_block_file );

# end of BIND process.

=head1

Now generating the SquidGuard blocking list.
In fact, the rules are already generated, we are only generating the SquidGuard configuration file here.

=cut

# print Dumper ( $squid_cat_to_generate );

open( $Fileout, ">$SquidGuard_conf_file" );

print $Fileout "#
# CONFIG FILE FOR SQUIDGUARD
#
# Caution: do NOT use comments inside { }
#

dbhome $SquidGuard_db_Env
logdir /var/log/squid

#
# DESTINATION CLASSES:
#

";

foreach my $cat ( keys %$squid_cat_to_generate ) {
    my $tcat = $cat;
    $tcat =~ s/\.//g;
    $tcat =~ s/\///g;
    print $Fileout "dest $tcat {\n";
    foreach my $type ( keys %{ $squid_cat_to_generate->{$cat} } ) {
        print $Fileout "  $type " . $squid_cat_to_generate->{$cat}{$type} . "\n";
    }
    print $Fileout "}\n";
    print $Fileout "\n";
}

print $Fileout "#
# ACL RULES:
#
";

print $Fileout "acl {\n";
print $Fileout "  default {\n";
print $Fileout "    pass   ";
foreach my $cat ( sort keys %$squid_cat_to_generate ) {
    my $tcat = $cat;
    $tcat =~ s/\.//g;
    $tcat =~ s/\///g;
    print $Fileout "!$tcat ";
}
print $Fileout "all\n";
print $Fileout "    pass !in-addr all\n";
print $Fileout "    pass !dnsbl:$rbldns_ip all\n";
print $Fileout "    redirect http://$ip4_redirector/block.html\n";
print $Fileout "  }\n";
print $Fileout "}\n";

close( $Fileout );

# end of SquidGuard process.

=head1

Now generating the RBLdns configuration and data blocking list.

=cut

my $Blacklist_tmp_rbl_aggr =
  `grep -v '^localhost\$' $Blacklist_tmp_rbldns_file | grep -v -e '^\$' | sort | uniq | egrep "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])(\/[0-9]{1,2})?\$"`;

# metaprint 'info', Dumper $Blacklist_tmp_rbl_aggr;

metaprint 'info', "RBLdns generating listing";
my $Blacklist_rbl_aggr;

# removing IP belonging to range.
#$Blacklist_rbl_aggr = generate_tree ( $Blacklist_Domain, $Bind_Blacklist_tmp_Domain, $Whitelist_Domain, $debug );

$Blacklist_rbl_aggr = $Blacklist_tmp_rbl_aggr;

# print Dumper ( $Blacklist_rbl_aggr );

open( $Fileout, ">$Rbldns_conf_file_new" );
print $Fileout ":$ip4_redirector:Known spammer, see http://$ip4_redirector/block.cgi?id=\$\n";
print $Fileout $Blacklist_rbl_aggr;
close $Fileout;

## -- Move tmp file to real one
$newsize = 0;
$newsize = -s $Rbldns_conf_file_new if ( -e $Rbldns_conf_file_new );

#
$cursize = 0;
$cursize = -s $Rbldns_conf_file_prod if ( -e $Rbldns_conf_file_prod );

#
$pctsize = 0;
$pctsize = ( ( $newsize - $cursize ) / $cursize ) * 100 if $cursize > 0;

#
if ( $newsize > 0 && $pctsize > -25 ) {
    if ( $pctsize > 25 ) {
        metaprint 'Warn', "RBLdns BlackList generated contains more than 25% growth... please check ASAP!";
    }
    move( $Rbldns_conf_file_prod, $Rbldns_conf_file_old );

    if ( move( $Rbldns_conf_file_new, $Rbldns_conf_file_prod ) ) {
        metaprint 'info', "RBLdns BlackList generated/updated correctly.";
    } else {
        metaprint 'critic', "Move of New RBLdns BlackList in production failed: $!";
        move( $Rbldns_conf_file_old, $Rbldns_conf_file_prod );
    }
} else {
    metaprint 'critic', "More than 25% of rows removed on the RBLdns black_list, problem suspected.";
    metaprint 'critic', "Process aborted.";
    exit( 1 );
}

# end of RBLdns process.

=head1

Now generating the nginx configuration and data blocking list.

=cut

my $Blacklist_tmp_nginx_aggr =
  `grep -v '^localhost\$' $Blacklist_tmp_rbldns_file | grep -v -e '^\$' | sort | uniq | egrep "^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])(\/[0-9]{1,2})?\$"`;

# metaprint 'info', Dumper $Blacklist_tmp_nginx_aggr;

metaprint 'info', "nginx generating listing";
my $Blacklist_nginx_aggr;

# removing IP belonging to range.
#$Blacklist_nginx_aggr = generate_tree ( $Blacklist_Domain, $Bind_Blacklist_tmp_Domain, $Whitelist_Domain, $debug );

$Blacklist_nginx_aggr = $Blacklist_tmp_nginx_aggr;

# print Dumper ( $Blacklist_nginx_aggr );

open( $Fileout, ">$nginx_conf_file_new" );
foreach my $l ( split( /\n/, $Blacklist_nginx_aggr ) ) {
    chomp $l;
    next if ( $l =~ /^\s*$/ );
    print $Fileout "deny $l;\n";
}
close $Fileout;

## -- Move tmp file to real one
$newsize = 0;
$newsize = -s $nginx_conf_file_new if ( -e $nginx_conf_file_new );

#
$cursize = 0;
$cursize = -s $nginx_conf_file_prod if ( -e $nginx_conf_file_prod );

#
$pctsize = 0;
$pctsize = ( ( $newsize - $cursize ) / $cursize ) * 100 if $cursize > 0;

#
if ( $newsize > 0 && $pctsize > -25 ) {
    if ( $pctsize > 25 ) {
        metaprint 'Warn', "nginx BlackList generated contains more than 25% growth... please check ASAP!";
    }
    move( $nginx_conf_file_prod, $nginx_conf_file_old );

    if ( move( $nginx_conf_file_new, $nginx_conf_file_prod ) ) {
        metaprint 'info', "nginx BlackList generated/updated correctly.";
    } else {
        metaprint 'critic', "Move of New nginx BlackList in production failed: $!";
        move( $nginx_conf_file_old, $nginx_conf_file_prod );
    }
} else {
    metaprint 'critic', "More than 25% of rows removed on the nginx black_list, problem suspected.";
    metaprint 'critic', "Process aborted.";
    exit( 1 );
}

# end of nginx process.

exit 0;
