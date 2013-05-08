#!/usr/bin/env perl

our $rcs_id = q$Id:$;

$|++;  # turn on autoflush
use strict;
use warnings;
use Data::Dumper;

my $separator     = "----------------------------------------------------------------";
my $os            = `uname`; chomp($os);
my $linux         = 1 if $os eq "Linux";
my $json_syck     = 0;
my $debug         = 0; 
my $rtrange       = 0; 
my $do_int_hdr    = 1; 
my $first         = 0;
my $summary       = 0; 
my $expect_nsid   = 1;
my $detail        = 0; # reporting detail, default is 0; or summary
my $printcount    = 0;
my $mid           = 0;
my $probeid       = 0;
my $max_queries   = 0;
my $ext_answers   = 0;
my $do_rt         = 1;
my $do_mn         = 1;
my $maxlines      = int 4294967295;
my $begin         = 1;
my $rtbucket_size = 300; # seconds
my $is_public     = 0;
my $description   = "";

while(@ARGV) {
  if (("x$ARGV[0]" eq "x-d") or ("x$ARGV[0]" eq "x-detail")) {
     $detail = 1;
     if (defined $ARGV[1] and $ARGV[1] =~ /^\d$/) {
        $detail = $ARGV[1];
        shift;
     }
     shift;
  } elsif ("x$ARGV[0]" eq "x-i") {
     if (defined $ARGV[1] and $ARGV[1] =~ /^\d*$/) {
        $rtbucket_size = $ARGV[1];
        shift;
     }
     shift;
  } elsif (("x$ARGV[0]" eq "x?") or ("x$ARGV[0]" eq "x--help") or ("x$ARGV[0]" eq "x-h")) {
     usage();
  } elsif ("x$ARGV[0]" eq "x-nonsid") {
     $expect_nsid = 0;
     shift;
  } elsif ("x$ARGV[0]" eq "x-rtrange") {
     $rtrange = 1;
     shift;
  } elsif ("x$ARGV[0]" eq "x-db") {
     $debug = 1;
     if (defined $ARGV[1] and $ARGV[1] =~ /^\d$/) {
        $debug = $ARGV[1];
        shift;
     }
     shift;
  } elsif ("x$ARGV[0]" eq "x-p") {
     if (defined $ARGV[1] and $ARGV[1] =~ /^\d*$/) {
        $probeid = $ARGV[1];
        shift;
        shift;
        next;
     } 
     usage("Invalid  or missing probeid");
  } elsif ("x$ARGV[0]" eq "x-s") {
     $summary = 1;
     if (defined $ARGV[1] and $ARGV[1] =~ /^\d$/) {
        $summary = $ARGV[1];
        shift;
     }
     shift;
  } elsif ("x$ARGV[0]" eq "x-m") {
     $mid   = $ARGV[1];
     shift;
     shift;
  } else {
     last;
  }
}

if (!$json_syck) {
   use JSON;
} else {
   require JSON::Syck;
}

my %abuf_rcodes      = ();
my %nsid_rcodes      = ();
my %nsids            = ();
my %headers          = ();
my %rcok_nonsid_hdrs = ();
my %rtbuckets        = ();
my %probes           = ();
my %probes_errors    = ();
my $interval         = sprintf "%d",$rtbucket_size/60;
my $headers          = 0;
my $noheaders        = 0;
my $nsids            = 0;
my $nonsids          = 0;
my $nsid_rcodes      = 0;
my $nonsid_rcodes    = 0;
my $nsidsreal        = 0;
my $probe_count      = 0;
my $probe_rt_count   = 0;
my $current_timeout  = 0;
my $current_senderror= 0;
my $current_othererror = 0;
my $current_header   = undef;
my $current_probe    = undef;
my $current_rt       = undef;
my $rtok_nonsid      = 0;
my $rcok_nonsid      = 0;
my $edns_nsid        = undef;
my $edns_rcode       = undef;
my $abuf_rcode       = undef;
my $abuf_noanswer    = 0;
my $noabuf_noanswer  = 0;
my $error_processing = 0;
my $ts               = "none";
my $ts_min           = int 4294967295;
my $ts_max           = int 0;
my %errors           = ();
my %rt               = ();
my %rtv              = ();
my %mn               = ();
my $rt_err           = 0;
my $rt_min           = 999999;
my $rt_max           = 0;
my $rt_cnt           = 0;
my $mn_cnt           = 0;
my $rt_pos           = 0;
my $rt_neg           = 0;
my $rt_too_large     = 0;
my $rt_avg           = 0;
my $rt_tot           = 0;
my $err_cnt          = 0;
my $eto_cnt          = 0;
my $ese_cnt          = 0;
my $an_cnt           = 0;
my $nan_cnt          = 0;
my $answer           = 0;
my $linecnt          = 0;
my $udmd;
my $t;

   print STDERR "ext_answers=$ext_answers\n" if $debug;
   print STDERR "Reading line by line from STDIN\n" if $summary or $debug;
   $linecnt = 0;
   $first   = 1;
   while (<>) {
      if ($probeid) {
         next if !/"prb_id":\s?$probeid,/;
      }
      if ($first) { # "msm_id": nnn,
         my ($udm) = $_ =~ /msm_id":\s?(\d*).*/;
         get_udm_meta_data($udm);
      }
      my ($ts) = $_ =~ /timestamp":\s?(\d*).*/;
      $ts_min= $ts if $ts < $ts_min;
      $ts_max= $ts if $ts > $ts_max;
      process_line($_);
      last if $linecnt >= $maxlines;
   }
   $t = `date`; chomp($t);
   printf "Processed a total of $linecnt measurements for measurement ID $mid%s",
          $probeid ? " for probeid $probeid\n" : "\n";
   my ($ns,$nm,$nh,$nD,$nM,$nY,$nwd,$nyd,$nisdst) = gmtime($ts_min);
   $nY+=1900; $nM+=1;
   my $ts_begin = sprintf("%2.2d-%2.2d-%2.2dT%2.2d:%2.2d:%2.2d", $nY, $nM, $nD, $nh, $nm, $ns);
   ($ns,$nm,$nh,$nD,$nM,$nY,$nwd,$nyd,$nisdst) = gmtime($ts_max);
   $nY+=1900; $nM+=1;
   my $ts_end   = sprintf("%2.2d-%2.2d-%2.2dT%2.2d:%2.2d:%2.2d", $nY, $nM, $nD, $nh, $nm, $ns);
   printf "Time period is from $ts_min to $ts_max or from $ts_begin to $ts_end\n";
   printf "Saw a total of $probe_count different probes, $probe_rt_count probes could reach destination\n";
   printf "$separator\n";
   print STDERR "ext_answers=$ext_answers\n" if $debug;

   if ($linecnt) {
      process_results();
      my $t = `date`; chomp($t);
      print "$separator\n$t Finished  processing measurement ID $mid\n" if $summary or $debug;
   } else {
      my $t = `date`; chomp($t);
      print "$separator\n$t Probably probe $probeid was not online or was not included in measurment ID "
      .     "$mid in the above listed period.\n";
   }
exit;

sub process_results {
    my $good_probes = 0;
    my $ok_probes   = 0;
    my $bad_probes  = 0;
    my $okp_queries = 90; # percentage of successful queries for an OK probe
    my $ok_queries  = int (($max_queries*$okp_queries)/100); # number of successful queries
       $ok_queries  = 1 if $ok_queries == 0;
    my %substantial = ();
    my %tresholds   = ('timeout' => 10, 'senderror' =>10, 'othererror' => 1,);
    foreach my $key (sort {$a <=> $b} keys %probes) {
        if ($max_queries == $probes{$key}) {
           $good_probes++;
           printf "probe %6s had %5d (max) successful measurement(s)\n", $key, $probes{$key} if $detail > 5;
        } elsif ($ok_queries <= $probes{$key}) {
           $ok_probes++;
           printf "probe %6s had %5d (from max $max_queries) successful measurement(s)\n", $key, $probes{$key} if $detail > 4;
        } else {
           $bad_probes++;
           printf "probe %6s had %5d (from max $max_queries) successful measurement(s)\n", $key, $probes{$key} if $detail > 3;
        }
        foreach my $k (keys %{$probes_errors{$key}}) {
           if ($probes_errors{$key}{$k} > $tresholds{$k}) {
              $substantial{$k}++;
              printf "probe %6s had %5d %11s measurement(s)\n", $key, $probes_errors{$key}{$k}, $k if $detail>2;
           } else {
              printf "probe %6s had %5d %11s measurement(s)\n", $key, $probes_errors{$key}{$k}, $k if $detail>3;
           }
        }
    }
    printf "We had %6d probes doing $max_queries successful measurements\n", $good_probes if $good_probes;
    printf "We had %6d probes doing between %d and $max_queries successful measurements\n", $ok_probes,$ok_queries if $ok_probes and $max_queries>$ok_queries+1;
    printf "We had %6d probes doing %d successful measurements\n", $ok_probes,$ok_queries if $ok_probes and $max_queries<=$ok_queries+1;
    printf "We had %6d probes doing between %d and $max_queries successful measurements\n", $ok_probes,$ok_queries if $ok_probes;
    printf "We had %6d probes doing less than %d successful measurements\n", $bad_probes, $ok_queries if $bad_probes;
    foreach my $k (keys %substantial) {
       printf "We had %6d probes with substantial (>$tresholds{$k}) $k errors\n", $substantial{$k};
    }
    print "$separator\n";
    if ($rt_cnt) {
       my $rtavg_tot = 0;
       my $rtavg_avg = 0;
       my $rt_avg   = $rt_tot/$rt_cnt if $rt_cnt;
       my $minm1    = $rt_avg -1; 
       my $minp1    = $rt_avg +1; 
       my $avgm     = 0;
       my $avgp     = 0;
       my $rt_avgp  = 0;
       foreach my $key (keys %rt) {
          $avgm++    if $rt{$key} <= $minm1;
          $avgp++    if $rt{$key} <= $minp1;
          $rt_avgp++ if $rt{$key} <= $rt_avg;
          my ($ts)   = $key =~ /(.*)\..*/; 
          my $bucket = int ($ts/$rtbucket_size); # xx mminute buckets
          $rtbuckets{$bucket}{cnt}++;
          $rtbuckets{$bucket}{val} += $rt{$key};
       }
       my $rt_avgpp = $rt_avgp*100/$rt_cnt;
       my $avgmp    = $avgm*100/$rt_cnt;
       my $avgpp    = $avgp*100/$rt_cnt;
       my $rtcnt    = 0;
       my $rt000p   = $rt_min;
       my $rt0025p  = 0;
       my $rt025p   = 0;
       my $rt050p   = 0;
       my $rt075p   = 0;
       my $rt080p   = 0;
       my $rt085p   = 0;
       my $rt090p   = 0;
       my $rt095p   = 0;
       my $rt0975p  = 0;
       my $rt100p   = $rt_max;
       my $rt0025c  = 0;
       my $rt025c   = 0;
       my $rt050c   = 0;
       my $rt075c   = 0;
       my $rt080c   = 0;
       my $rt085c   = 0;
       my $rt090c   = 0;
       my $rt095c   = 0;
       my $rt0975c  = 0;
       my $rt100c   = 0;
       foreach my $key (sort { $a <=> $b } keys %rtv) {
          $rtcnt  += $rtv{$key};
          $rt0025p = $key if $rtcnt <= $rt_pos*2.5/100;
          $rt025p  = $key if $rtcnt <= $rt_pos*25/100;
          $rt050p  = $key if $rtcnt <= $rt_pos*50/100;
          $rt075p  = $key if $rtcnt <= $rt_pos*75/100;
          $rt080p  = $key if $rtcnt <= $rt_pos*80/100;
          $rt085p  = $key if $rtcnt <= $rt_pos*85/100;
          $rt090p  = $key if $rtcnt <= $rt_pos*90/100;
          $rt095p  = $key if $rtcnt <= $rt_pos*95/100;
          $rt0975p = $key if $rtcnt <= $rt_pos*97.5/100;
          $rt0025c = $rtcnt if $rtcnt <= $rt_pos*2.5/100;
          $rt025c  = $rtcnt if $rtcnt <= $rt_pos*25/100;
          $rt050c  = $rtcnt if $rtcnt <= $rt_pos*50/100;
          $rt075c  = $rtcnt if $rtcnt <= $rt_pos*75/100;
          $rt080c  = $rtcnt if $rtcnt <= $rt_pos*80/100;
          $rt085c  = $rtcnt if $rtcnt <= $rt_pos*85/100;
          $rt090c  = $rtcnt if $rtcnt <= $rt_pos*90/100;
          $rt095c  = $rtcnt if $rtcnt <= $rt_pos*95/100;
          $rt0975c = $rtcnt if $rtcnt <= $rt_pos*97.5/100;
          if ($rtcnt > ($rt_pos*2.5/100) and $rtcnt < ($rt_pos*97.5/100)) {
             $rtavg_tot += ($rtv{$key} * $key);
          }
       }
#my $fcnt=0;
       my $next_bucket = 0;
       foreach my $bucket (sort keys %rtbuckets) {
          $next_bucket += $rtbucket_size if $next_bucket; 
          $next_bucket  = $bucket*$rtbucket_size if !$next_bucket; 
          my ($es,$em,$eh,$eD,$eM,$eY,$ewd,$eyd,$eisdst) = gmtime($bucket*$rtbucket_size+$rtbucket_size);
          my ($ss,$mm,$hh,$DD,$MM,$YY,$wd,$yd,$isdst)    = gmtime($bucket*$rtbucket_size);
          $YY+=1900; $MM+=1;
          my $gap = 0;
          my $thisbucket = $bucket*$rtbucket_size;
          my $gapbucket  = $next_bucket;
          while ($next_bucket != $thisbucket) {
             $gap = 1;
             my ($es,$em,$eh,$eD,$eM,$eY,$ewd,$eyd,$eisdst) = gmtime($next_bucket+$rtbucket_size);
             my ($ss,$mm,$hh,$DD,$MM,$YY,$wd,$yd,$isdst)    = gmtime($next_bucket);
             $YY+=1900; $MM+=1;
             $next_bucket +=$rtbucket_size;
          }
          if ($gap) {
             my ($ns,$nm,$nh,$nD,$nM,$nY,$nwd,$nyd,$nisdst) = gmtime($gapbucket);
             $nY+=1900; $nM+=1;
             my ($ens,$enm,$enh,$enD,$enM,$enY,$enwd,$enyd,$enisdst) = gmtime($next_bucket - 60);
             $enY+=1900; $enM+=1;
             print  "#timestamp ---date--- -interval-- -probes- -avg_dns_rt timeouts REFUSED-\n" if $do_int_hdr;
             $do_int_hdr = 0;
             printf "%10d %2.2d-%2.2d-%2.2d %2.2d:%2.2d-%2.2d:%2.2d %8.8d %10.4f %8.8d %8.8d - no data for this period\n",
                 int ($gapbucket), $nY, $nM, $nD, $nh, $nm, $enh, $enm,
                 0,0,0,0;
          }

          if (!defined $rtbuckets{$bucket}{val}) {
             print  "#timestamp ---date--- -interval-- -probes- -avg_dns_rt timeouts REFUSED-\n" if $do_int_hdr;
             $do_int_hdr = 0;
             printf "%10d %2.2d-%2.2d-%2.2d %2.2d:%2.2d-%2.2d:%2.2d %8.8d %10.4f %8.8d %8.8d - no data for this period\n",
                 int ($bucket*$rtbucket_size), $YY, $MM, $DD, $hh, $mm, $eh, $em,
                 defined $rtbuckets{$bucket}{cnt} ? $rtbuckets{$bucket}{cnt} : 0,
                 defined $rtbuckets{$bucket}{val} ? $rtbuckets{$bucket}{val} : 0,
                 defined $rtbuckets{$bucket}{err_cnt} ? $rtbuckets{$bucket}{err_cnt} : 0,
                 defined $rtbuckets{$bucket}{refused} ? $rtbuckets{$bucket}{refused} : 0;
             next;
          }
          if ($rtbuckets{$bucket}{val}/$rtbuckets{$bucket}{cnt} > $rt090p) {
             print  "#timestamp ---date--- -interval-- -probes- -avg_dns_rt timeouts REFUSED-\n" if $do_int_hdr;
             $do_int_hdr = 0;
             printf "%10d %2.2d-%2.2d-%2.2d %2.2d:%2.2d-%2.2d:%2.2d %8.8d %10.4f %8.8d %8.8d - avg rt above $rt090p (90th percentile)\n",
                 int ($bucket*$rtbucket_size), $YY, $MM, $DD, $hh, $mm, $eh, $em,
                 $rtbuckets{$bucket}{cnt}, $rtbuckets{$bucket}{val}/$rtbuckets{$bucket}{cnt},
                 defined $rtbuckets{$bucket}{err_cnt} ? $rtbuckets{$bucket}{err_cnt} : 0,
                 defined $rtbuckets{$bucket}{refused} ? $rtbuckets{$bucket}{refused} : 0;
            }
       }
       $rt100c     = $rtcnt;
       $rtavg_avg  = ($rtavg_tot/$rt_pos) if $rt_pos;
       if ($do_rt) {
          if ($summary) {
             printf "rt values \t%8d\t%6.2f%% is all responses with any rt value\n",$rt_cnt, 100;
             printf "rt values \t%8d\t%6.2f%% has an rt <= $minm1\n", $avgm, $avgmp,;
             printf "rt values \t%8d\t%6.2f%% has an rt <= $rt_avg\n",$rt_avgp, $rt_avgpp;
             printf "rt values \t%8d\t%6.2f%% has an rt <= $minp1\n",$avgp, $avgpp;
             printf "Average rt\t%8.2f\n",$rt_avg;
             printf "Minimum rt\t%8.2f\n",$rt_min;
             printf "Maximum rt\t%8.2f\n",$rt_max;
             print  "$separator\n";
          }
          if  ($detail > 5) {
             printf "Timeouts  \t%8d\n",$eto_cnt;
             printf "Errors    \t%8d\n",$err_cnt;
             printf "rt <=0    \t%8d\n",$rt_neg;
             printf "0<rt<=5000\t%8d\n",$rt_pos;
             printf "rt >5000  \t%8d\n",$rt_too_large;
             print  "$separator\n";
          }
          print "$separator\n" if !$do_int_hdr;
          printf "%8s  cumulative percentile with       an rt value of\n","count";
          print "$separator\n" if !$do_int_hdr;
          printf "%8d       0   Percentile with            rt <= %8.3f\n",1,$rt000p;
          printf "%8d       2.5 Percentile with            rt <= %8.3f\n",$rt0025c,$rt0025p;
          printf "%8d      25   Percentile with            rt <= %8.3f\n",$rt025c,$rt025p;
          printf "%8d      50   Percentile with            rt <= %8.3f\n",$rt050c,$rt050p;
          printf "%8d      75   Percentile with            rt <= %8.3f\n",$rt075c,$rt075p;
          printf "%8d      80   Percentile with            rt <= %8.3f\n",$rt080c,$rt080p;
          printf "%8d      85   Percentile with            rt <= %8.3f\n",$rt085c,$rt085p;
          printf "%8d      90   Percentile with            rt <= %8.3f\n",$rt090c,$rt090p;
          printf "%8d      95   Percentile with            rt <= %8.3f\n",$rt095c,$rt095p;
          printf "%8d      97.5 Percentile with            rt <= %8.3f\n",$rt0975c,$rt0975p;
          printf "%8d     100   Percentile with            rt <= %8.3f\n",$rt100c,$rt100p;
          printf "%8d  2.5-97.5 Percentile with %8.3f < rt <  %8.3f    with average rt %8.3f\n",
                 $rt0975c-$rt0025c,$rt0025p,$rt0975p,$rtavg_avg;
          print  "$separator\n";
       }
    } else {
       if ($do_rt) {
          print "\tNo valid rt values found\n";
          print "\tErrors in responses\t$err_cnt\n";
          print "\tRt with negative   \t$rt_neg\n";
       }
    } 
    my $one_perc = $linecnt/100;
    my $rt1_perc = $rt_cnt/100;
       $rt1_perc = $rt_pos/100;
    my $perc     = 100;
    my $rtperc   = 100;
    if ($mn_cnt) {
       if ($do_mn) {
          foreach my $mnk (sort keys %mn) {
             $perc   = $mn{$mnk}/$one_perc;
             $rtperc = $mn{$mnk}/$rt1_perc;
             printf "Total responses with MNAME %30s       %8d %6.2f%% %6.2f%%\n", $mnk, $mn{$mnk}, $perc, $rtperc;
          }
          if ($summary) {
             printf "Total with MNAME answer:  \t%8d\t%6.2f%%\n", $mn_cnt, $mn_cnt/$one_perc;
             printf "Total with an answer:     \t%8d\t%6.2f%%\n", $an_cnt, $an_cnt/$one_perc;
             printf "Total without any answer: \t%8d\t%6.2f%%\n", $nan_cnt, $nan_cnt/$one_perc;
             printf "Total errors:             \t%8d\t%6.2f%%\n", $err_cnt, $err_cnt/$one_perc;
             printf "Total errors (timeout):   \t%8d\t%6.2f%%\n", $eto_cnt, $eto_cnt/$one_perc;
             printf "Total errors (senderror): \t%8d\t%6.2f%%\n", $ese_cnt, $ese_cnt/$one_perc;
             print  "$separator\n";
             $err_cnt = 0;
             foreach my $key (sort keys %errors) {
                printf "Total errors %-16s\t%8d\t%6.2f%%\n", $key, $errors{$key}, $errors{$key}/$one_perc;
                $err_cnt += $errors{$key};
             }
             printf "Total errors:             \t%8d\t%6.2f%%\n", $err_cnt, $err_cnt/$one_perc;
             my $arc_cnt = 0;
             foreach my $key (sort keys %abuf_rcodes) {
                printf "Total abuf rcodes %-8s \t%8d\t%6.2f%%\n", $key, $abuf_rcodes{$key}, $abuf_rcodes{$key}/$one_perc;
                $arc_cnt += $abuf_rcodes{$key};
             }
             printf "Total rcodes:            \t%8d\t%6.2f%%\n", $arc_cnt, $arc_cnt/$one_perc;
             printf "Total abuf but no answer \t%8d\t%6.2f%%\n", $abuf_noanswer, $abuf_noanswer/$one_perc;
             printf "Total noabuf and noanswer\t%8d\t%6.2f%%\n\n", $noabuf_noanswer, $noabuf_noanswer/$one_perc;
             print  "$separator\n";
          }

          my $nsidssum = 0;
          foreach my $key (sort keys %nsids) {
             $nsidssum += $nsids{$key};
             if ($detail > 0) {
                printf "Total count for NSID            %25s       %8d %6.2f%% %6.2f%%\n",
                    $key, $nsids{$key}, $nsids{$key}/$one_perc, $nsids{$key}*100/$nsids;
             }
          }
                printf "Total count for all NSIDs       %25s       %8d %6.2f%% %6.2f%%\n",
                 "", $nsids, $nsids/$one_perc, $nsids*100/$nsids if $nsids;
          if ($summary) {
             printf "Total count without NSID  %25s\t%8d\t%6.2f%%\n", "", $nonsids, $nonsids/$one_perc;
             printf "Total nsids $nsids, total nonsids $nonsids, total nsidsreal $nsidsreal, above summed $nsidssum\n";
          }
          if ($expect_nsid and $nonsids) {
             #printf "Total valid rt but no NSID: $rtok_nonsid\n";
             printf "Total responses with a ReturnCode==NOERROR but no NSID: $rcok_nonsid\n";
             printf "From which:\n";
             foreach my $AARA (sort keys %rcok_nonsid_hdrs) {
                printf "  with header fields %s: %6d\n", uc($AARA), $rcok_nonsid_hdrs{$AARA};
             }
          }

          print  "$separator\n";
          my $headerssum = 0;
          my $aa0ra1     = 0;
          my $aa1ra0     = 0;
          my $aa1ra1     = 0;
          my $aa0rax     = 0;
          my $aaxrax     = 0;
          foreach my $key (sort keys %headers) {
             $headerssum += $headers{$key};
             if ($key !~ /NOERROR/) {
                if ($detail > 5) {
                   printf "Total count for HEADER %-80s\t%8d\t%6.2f%%\t%6.2f%%\n",
                    $key, $headers{$key}, $headers{$key}/$one_perc, $headers{$key}*100/$headers if $summary;
                }
                my ($rcode, $aa, $ra) = $key =~ /.*rcode=\s+(\S*)\s.*aa=(\d+)\s+ra=(\d+)\s.*/; 
                printf "Responses with ReturnCode %8s (header fields AA=$aa RA=$ra):  %8d %6.2f%% %6.2f%%\n",
                       $rcode, $headers{$key}, $headers{$key}/$one_perc, $headers{$key}*100/$headers;
                next;
             }
             if ($key =~ /aa=0 ra=1/) {
                if ($detail > 5) {
                   printf "Total count for HEADER %-80s\t%8d\t%6.2f%%\t%6.2f%%\n",
                       $key, $headers{$key}, $headers{$key}/$one_perc, $headers{$key}*100/$headers;
                }
                $aa0ra1 += $headers{$key};
             } elsif ( $key =~ /aa=1 ra=0/) {
                if ($detail > 5) {
                   printf "Total count for HEADER %-80s\t%8d\t%6.2f%%\t%6.2f%%\n",
                       $key, $headers{$key}, $headers{$key}/$one_perc, $headers{$key}*100/$headers;
                }
                $aa1ra0 += $headers{$key};
             } elsif ( $key =~ /aa=1 ra=1/) {
                if ($detail > 5) {
                   printf "Total count for HEADER %-80s\t%8d\t%6.2f%%\t%6.2f%%\n",
                       $key, $headers{$key}, $headers{$key}/$one_perc, $headers{$key}*100/$headers;
                }
                $aa1ra1 += $headers{$key};
             } elsif ($key =~ /aa=0/) { # and ra != 1
                if ($detail > 5) {
                   printf "Total count for HEADER %-80s\t%8d\t%6.2f%%\t%6.2f%%\n",
                       $key, $headers{$key}, $headers{$key}/$one_perc, $headers{$key}*100/$headers;
                }
                $aa0rax += $headers{$key};
             } else { # something else
                if ($detail > 5) {
                   printf "Total count for HEADER %-80s\t%8d\t%6.2f%%\t%6.2f%%\n",
                       $key, $headers{$key}, $headers{$key}/$one_perc, $headers{$key}*100/$headers;
                }
                $aaxrax += $headers{$key};
             }
          }
          if ($summary) {
             printf "Total count for all HEADERS %75s\t%8d\t%6.2f%%\t%6.2f%%\n",
                    "", $headers, $headers/$one_perc, $headers*100/$headers;
             printf "Total count without HEADER  %75s\t%8d\t%6.2f%%\n",
                    "", $noheaders, $noheaders/$one_perc;
             printf "Total headers $headers, total noheaders $noheaders, above summed $headerssum\n";

             print  "$separator\n";
          }
          printf "Correct (expected) responses       (header fields AA=1 RA=0):   %8d %6.2f%% %6.2f%%\n",
                       $aa1ra0, $aa1ra0/$one_perc, $aa1ra0*100/$headers;
          printf "Intercepted responses              (header fields AA=0 RA=1):   %8d %6.2f%% %6.2f%%\n",
                       $aa0ra1, $aa0ra1/$one_perc, $aa0ra1*100/$headers if $aa0ra1;
          printf "Intercepted responses              (header fields AA=1 RA=1):   %8d %6.2f%% %6.2f%%\n",
                       $aa1ra1, $aa0ra1/$one_perc, $aa1ra1*100/$headers if $aa1ra1;
          printf "Weird (unexpected) responses       (header fields AA=0 RA!=1):  %8d %6.2f%% %6.2f%%\n",
                       $aa0rax, $aa0rax/$one_perc, $aa0rax*100/$headers if $aa0rax;
          printf "Other (unexpected) responses (header AA and RA none of above):  %8d %6.2f%% %6.2f%%\n",
                       $aaxrax, $aaxrax/$one_perc, $aaxrax*100/$headers if $aaxrax;
          my $nsidsrcsum = 0;
          foreach my $key (sort keys %nsid_rcodes) {
             $nsidsrcsum += $nsid_rcodes{$key};
             my $doprint = 0;
             $doprint = 1 if ($key == 0 and $detail >2);
             $doprint = 1 if ($key != 0);
             printf "Total count for NSID edns_rcode %19s             %8d %6.2f%% %6.2f%%\n",
                     $key, $nsid_rcodes{$key}, $nsid_rcodes{$key}/$one_perc, $nsid_rcodes{$key}*100/$nsids if $doprint;
          }
          printf "Total nsid_rcodes $nsid_rcodes, total nonsid_rcodess $nonsid_rcodes, above summed $nsidsrcsum\n" if $summary;
       } 
       print "                                                                            ^       ^\n";
       print "Percentage of ALL measurement records ======================================+       |\n";
       print "Percentage of all measurements with 0 < rt <5000 ===================================+\n";
    } 
}

sub process_line {
    my ($line) = @_;
#   $line =~ s/, }$/}/;
    $linecnt++;
    $ext_answers = 1;
    $answer        = 0;
    $abuf_rcode    = undef;
    $edns_rcode    = undef;
    $edns_nsid     = undef;
    $current_probe = undef;
    $current_header= undef;
    $current_rt    = undef;
    $rt_err        = 0;
    $current_timeout    = 0;
    $current_senderror  = 0;
    $current_othererror = 0;
    $nonsids++       if $ext_answers; # will reduce again if NSID found
    $nonsid_rcodes++ if $ext_answers; # will reduce again if NSID found
    $noheaders++     if $ext_answers; # will reduce again if NSID found
    if (!($linecnt%10000)) {
       my $t = `date`; chomp($t);
       print STDERR "$t Did $linecnt lines\n" if !($linecnt%10000) and $summary;
    }
    if (!$json_syck) {
       if ($first) {
          my $pp = JSON->backend->is_pp; # 0 or 1
          my $xs = JSON->backend->is_xs; # 0 or 1
          print STDERR "Using plain JSON version $JSON::VERSION, PP=$pp, XS=$xs\n"
             if $first and ($summary or $debug);
       }
       eval {
           $udmd = from_json($line);
       }; if ($@) {
           print STDERR "Trouble at line $linecnt\nline------\n$line\n"
           .     "udmd------\n" . Dumper($udmd) ."\n";
       } else {
           print STDERR "OK! $linecnt\n" if $debug >2;
       }
    } else {
       print STDERR "Using JSON::Syck\n" if ($summary or $debug) and $first;
       eval {
           $udmd = JSON::Syck::Load($line);
       }; if ($@) {
           print STDERR "Trouble at line $linecnt\nline------\n$line\n"
           .     "udmd------\n" . Dumper($udmd) ."\n";
       } else {
           print STDERR "OK! $linecnt\n" if $debug >2;
       }
    }
    process_array_entry($udmd) if $do_mn or $probeid;
    $first = 0;
    $an_cnt++  if $answer;
    $nan_cnt++ if !$answer;
    if (defined $abuf_rcode) {
       $abuf_rcodes{$abuf_rcode}++;
       $abuf_noanswer++ if !$answer;
       if ($abuf_rcode eq "NOERROR" and !defined $edns_nsid) {
          $rcok_nonsid++;
          my ($AARA) = $current_header =~ /.*(aa=\d* ra=\d*).*/;
          $rcok_nonsid_hdrs{$AARA}++;
       }   
    } else {
       $abuf_rcodes{"no_rcode"}++;
       $noabuf_noanswer++ if !$answer;
       $nonsids++         if !$answer and !$ext_answers;
       $nonsid_rcodes++   if !$answer and !$ext_answers;
    }
    if (defined $probes{$current_probe} and defined $current_rt) {
       $probe_rt_count++ if $probes{$current_probe} <1;
       $probes{$current_probe}++;
       $max_queries = $probes{$current_probe} if $max_queries < $probes{$current_probe};
    } elsif (!defined $probes{$current_probe} and defined $current_rt) {
       $probe_count++;
       $probe_rt_count++;
       $probes{$current_probe} = 1;
    } elsif (!defined $probes{$current_probe} and !defined $current_rt) {
       $probes{$current_probe} = 0;
    }
    if (!defined $current_rt) {
       $probes_errors{$current_probe}{timeout}++ if $current_timeout;
       $probes_errors{$current_probe}{senderror}++ if $current_senderror;
       $probes_errors{$current_probe}{othererror}++ if $current_othererror;
    }
    $rtok_nonsid++ if defined $current_rt and !defined $edns_nsid;
    return;
}

sub process_array_entry {
    my ($pt, $undef) = @_;
    if (ref($pt) eq "ARRAY") {
       foreach my $at (@$pt) {
          process_array_entry($at);
       }
    } elsif (ref($pt) eq "HASH") {
       process_hash($pt);
    } else {
       print "====> unknown struct:" .  Dumper($pt) . "\n" if $debug;
       print STDERR "====> unknown struct at line $linecnt:" .  Dumper($pt) . "\n";
    }
}

sub process_hash {
    my ($pt, $undef) = @_;
    foreach my $key (keys %$pt) {
       $answer = 1 if "$key" eq "answers";
       if (ref($pt->{$key}) eq "ARRAY") {
	  foreach my $at (@{$pt->{$key}}) {
             if ("$key" eq "ERROR") {
                print "Found ERROR array\n" if $debug;
                $errors{'ERROR'}++;
             } else {
                process_array_entry($at);
             }
          }
       } elsif (ref($pt->{$key}) eq "HASH") {
          if ("$key" eq "HEADER") {
             my $nkey = "";
             $nkey  = "rcode= $pt->{$key}->{'ReturnCode'}";
             $nkey .= " qr=";
             $nkey .= ($pt->{$key}->{'QR'} eq "true") ? 1 : 0;
             $nkey .= " aa=";
             $nkey .= ($pt->{$key}->{'AA'} eq "true") ? 1 : 0;
             $nkey .= " ra=";
             $nkey .= ($pt->{$key}->{'RA'} eq "true") ? 1 : 0;
             $nkey .= " tc=";
             $nkey .= ($pt->{$key}->{'TC'} eq "true") ? 1 : 0;
             $nkey .= " rd=";
             $nkey .= ($pt->{$key}->{'RD'} eq "true") ? 1 : 0;
             $nkey .= " qd=";
             $nkey .= $pt->{$key}->{'QDCOUNT'};
             $nkey .= " an=";
             $nkey .= $pt->{$key}->{'ANCOUNT'};
             $nkey .= " ns=";
             $nkey .= $pt->{$key}->{'NSCOUNT'};
             $nkey .= " ar=";
             $nkey .= $pt->{$key}->{'ARCOUNT'};
             #print "nkey=$nkey\n";
             $headers{$nkey}++;
             $headers++;
             $noheaders-- if $ext_answers;
             $current_header = $nkey;
          }
          $err_cnt++ if "$key" eq "error";
          $error_processing = 1 if "$key" eq "error";
          process_hash($pt->{$key});
          $error_processing = 0 if $key eq "error";
       } else {
          if (!$ext_answers and $key eq "abuf") { 
             #means that we have an abuf, but it has not yet been fully decoded
          } else {
             if ("$key" eq "timestamp") {
                $ts = $pt->{$key};
                $ts_min = $ts if $ts < $ts_min;
                $ts_max = $ts if $ts > $ts_max;
             }
             if ("$key" eq "MNAME") { # for DNS SOA measurements
                my $mn_value = $pt->{$key};
                $mn{$mn_value}++;
                $mn_cnt++;
             } elsif ($key eq "rcode" or $key eq "ReturnCode") {
                $abuf_rcode = $pt->{$key};
                if ($abuf_rcode eq "REFUSED") {
                   my $bucket = int ($ts/$rtbucket_size);
                   $rtbuckets{$bucket}{refused}++;
                }
             } elsif ($key eq "ExtendedReturnCode") {
                $nsid_rcodes{$pt->{$key}}++;
                $nonsid_rcodes-- if $ext_answers;
                $nsid_rcodes++ if $ext_answers;
                $edns_rcode = $pt->{$key};
             } elsif ($key eq "NSID") {
                $nsids{$pt->{$key}}++;
                $nsids++;
                $nonsids-- if $ext_answers; # ah we do have one
                $edns_nsid = $pt->{$key};
             } elsif ($key eq "header") { # should not occur with new code
                $headers{$pt->{$key}}++;
                $headers++;
                $noheaders-- if $ext_answers; # ah we do have one
             } elsif ($key eq "prb_id") {
                $current_probe = $pt->{$key};
                if (!defined $probes{$current_probe}) {
                   $probe_count++;
                   $probes{$current_probe} = 0;
                }
             } elsif ($do_rt and "$key" eq "rt") { # for DNS measurements
                my $rt_val = $pt->{$key};
                if ($rt_val > 5000) {
                   $rt_err = $rt_val;
                   $rt_too_large++;
                   print STDERR "probe = $current_probe, rt = $rt_val for line $linecnt\n" if $debug;
                } elsif ($rt_val > 0) {
                   my $i = 0;  
                   while (defined $rt{"$ts.$i"}) {
                       $i++;
                   }
                   $current_rt = $rt_val;
                   $rt{"$ts.$i"} = $rt_val;
                   $rt_tot   += $rt_val;
                   $rt_min    = $rt_val if $rt_min > $rt_val;
                   $rt_max    = $rt_val if $rt_max < $rt_val;
                   $rtv{$rt_val}++;
                   $rt_pos++;
                } else {
                   $rt_err = $rt_val;
                   $rt_neg++;
                   print STDERR "probe = $current_probe, rt = $rt_val for line $linecnt\n" if $debug;
                }
                $rt_cnt++;
             }
             if ($error_processing) {
                my $bucket = int ($ts/$rtbucket_size);
                if ("$key" eq "timeout") {
                   $rtbuckets{$bucket}{err_cnt}++;
                   $current_timeout = 1;
                   $eto_cnt++;
                } elsif ("$key" eq "senderror") {
                   $current_senderror = 1;
                   $ese_cnt++;
                } else {
                   $current_othererror = 1;
                }
                $errors{$key}++;
             }
          }
       }
    }
}

sub usage {
   print "\n@_\n\n";
   print "Usage: $0 [-flags]\n\n";
   print "Flags:\n";
   print " -d[etail] lvl  to print details, higher level is more detail, default is 0 (i.e. summary)\n";
#  print " -m msm-id      only process specified measurement ID (UDM id)\n";
#  print " -p probe-id    find data for this probeid (default=0; i.e. all probes)\n";
   print " -i interval    measurment interval in seconds, default 300)\n";
#  print " -nonsid        no NSIDs expected\n";
   print "Input comes from STDIN; should be DNS related measurements\n";
   print "Output hoes to STDOUT (plain results) and STDERR (info and error msgs)\n";
   exit 2;
}

sub get_udm_meta_data {
   ($mid) = @_;
   my $udm = "";
   my $cmd = "wget -O- --no-check-certificate \"https://atlas.ripe.net/api/v1/measurement/$mid/?fields=interval,description,is_one_off,is_public,nsid\" 2>/dev/null"; #,probe_sources\"";
      $cmd = "curl -G \"https://atlas.ripe.net/api/v1/measurement/$mid/?fields=interval,description,is_one_off,is_public,nsid\" 2>/dev/null"; #,probe_sources\"";
   print STDERR "using: $cmd\n" if $summary or $debug;
   $udm = `$cmd`;
   my $size=length($udm);
   print STDERR "received $size bytes of meta data\n" if $summary or $debug;
   if (!$size) {
      print STDERR "Could not obtain any meta data for measurement ID $mid assume interval of 1800 seconds\n";
      $rtbucket_size = 1800; # seconds
      undef $udm;
   } else {
      print "udm meta data:\n$udm\n" if $debug;
      my $udm_meta;
      if (!$json_syck) {
         eval {
            $udm_meta = from_json($udm);
         }; if ($@) {
            print STDERR "Trouble decoding meta data\n"
            .     "------\n" . Dumper($udm) ."\n";
         } 
      } else {
         eval {
            $udm_meta = JSON::Syck::Load($udm);
         }; if ($@) {
            print STDERR "Trouble decoding meta data\n"
            .     "------\n" . Dumper($udm) ."\n";
         }
      }
      foreach my $key (sort keys %$udm_meta) {
         printf "%15s: %s\n", $key, defined $udm_meta->{$key} ? $udm_meta->{$key} : "" if $debug;    
         if ($key eq "interval") {
            $rtbucket_size = $udm_meta->{$key} if defined $udm_meta->{$key}; # seconds
            $interval      = sprintf "%d",$rtbucket_size/60;
         } elsif ($key eq "nsid") {
            $expect_nsid = $udm_meta->{$key} eq "true" ? 1 : 0;
         } elsif ($key eq "is_public") {
            $is_public   = $udm_meta->{$key} eq "true" ? 1 : 0;
         } elsif ($key eq "description") {
            $description = $udm_meta->{$key};
         }
      }
   }
}
exit 0;
