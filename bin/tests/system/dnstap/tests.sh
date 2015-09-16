#!/bin/sh
#
# Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

RNDCCMD="$RNDC -p 9953 -c ../common/rndc.conf"

status=0

$DIG +short @10.53.0.3 -p 5300 a.example > dig.out
sleep 1

# XXX: file output should be flushed once a second according
# to the libfstrm source, but it doesn't seem to happen until
# enough data has accumulated. to get all the output, we stop
# the name servers, forcing a flush on shutdown. it would be
# nice to find a better way to do this.
$RNDCCMD -s 10.53.0.1 stop | sed 's/^/I:ns1 /'
$RNDCCMD -s 10.53.0.2 stop | sed 's/^/I:ns2 /'
$RNDCCMD -s 10.53.0.3 stop | sed 's/^/I:ns3 /'
sleep 1

udp1=`$DNSTAPREAD ns1/dnstap.out | grep "UDP " | wc -l`
tcp1=`$DNSTAPREAD ns1/dnstap.out | grep "TCP " | wc -l`
aq1=`$DNSTAPREAD ns1/dnstap.out | grep "AQ " | wc -l`
ar1=`$DNSTAPREAD ns1/dnstap.out | grep "AR " | wc -l`
cq1=`$DNSTAPREAD ns1/dnstap.out | grep "CQ " | wc -l`
cr1=`$DNSTAPREAD ns1/dnstap.out | grep "CR " | wc -l`
rq1=`$DNSTAPREAD ns1/dnstap.out | grep "RQ " | wc -l`
rr1=`$DNSTAPREAD ns1/dnstap.out | grep "RR " | wc -l`

udp2=`$DNSTAPREAD ns2/dnstap.out | grep "UDP " | wc -l`
tcp2=`$DNSTAPREAD ns2/dnstap.out | grep "TCP " | wc -l`
aq2=`$DNSTAPREAD ns2/dnstap.out | grep "AQ " | wc -l`
ar2=`$DNSTAPREAD ns2/dnstap.out | grep "AR " | wc -l`
cq2=`$DNSTAPREAD ns2/dnstap.out | grep "CQ " | wc -l`
cr2=`$DNSTAPREAD ns2/dnstap.out | grep "CR " | wc -l`
rq2=`$DNSTAPREAD ns2/dnstap.out | grep "RQ " | wc -l`
rr2=`$DNSTAPREAD ns2/dnstap.out | grep "RR " | wc -l`

udp3=`$DNSTAPREAD ns3/dnstap.out | grep "UDP " | wc -l`
tcp3=`$DNSTAPREAD ns3/dnstap.out | grep "TCP " | wc -l`
aq3=`$DNSTAPREAD ns3/dnstap.out | grep "AQ " | wc -l`
ar3=`$DNSTAPREAD ns3/dnstap.out | grep "AR " | wc -l`
cq3=`$DNSTAPREAD ns3/dnstap.out | grep "CQ " | wc -l`
cr3=`$DNSTAPREAD ns3/dnstap.out | grep "CR " | wc -l`
rq3=`$DNSTAPREAD ns3/dnstap.out | grep "RQ " | wc -l`
rr3=`$DNSTAPREAD ns3/dnstap.out | grep "RR " | wc -l`

echo "I:checking UDP message counts"
ret=0
[ $udp1 -eq 0 ] || {
        echo "ns1 $udp1 expected 0" ; ret=1
}
[ $udp2 -eq 4 ] || {
        echo "ns2 $udp2 expected 4" ; ret=1
}
[ $udp3 -eq 8 ] || {
        echo "ns3 $udp3 expected 8" ; ret=1
}
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking TCP message counts"
ret=0
[ $tcp1 -eq 6 ] || {
        echo "ns1 $tcp1 expected 6" ; ret=1
}
[ $tcp2 -eq 2 ] || {
        echo "ns2 $tcp2 expected 2" ; ret=1
}
[ $tcp3 -eq 6 ] || {
        echo "ns3 $tcp3 expected 6" ; ret=1
}
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking AUTH_QUERY message counts"
ret=0
[ $aq1 -eq 2 ] || {
        echo "ns1 $aq1 exepcted 2" ; ret=1
}
[ $aq2 -eq 2 ] || {
        echo "ns2 $aq2 expected 2" ; ret=1
}
[ $aq3 -eq 0 ] || {
        echo "ns3 $aq3 expected 0" ; ret=1
}
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking AUTH_RESPONSE message counts"
ret=0
[ $ar1 -eq 2 ] || {
        echo "ns1 $ar1 expected 2" ; ret=1
}
[ $ar2 -eq 2 ] || {
        echo "ns2 $ar2 expected 2" ; ret=1
}
[ $ar3 -eq 0 ] || {
        echo "ns3 $ar3 expected 0" ; ret=1
}
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking CLIENT_QUERY message counts"
ret=0
[ $cq1 -eq 1 ] || {
        echo "ns1 $cq1 expected 1" ; ret=1
}
[ $cq2 -eq 1 ] || {
        echo "ns2 $cq2 expected 1" ; ret=1
}
[ $cq3 -eq 3 ] || {
        echo "ns3 $cq3 expected 3" ; ret=1
}
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking CLIENT_RESPONSE message counts"
ret=0
[ $cr1 -eq 1 ] || {
        echo "ns1 $cr1 expected 1" ; ret=1
}
[ $cr2 -eq 1 ] || {
        echo "ns2 $cr2 expected 1" ; ret=1
}
[ $cr3 -eq 3 ] || {
        echo "ns3 $cr3 expected 3" ; ret=1
}
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking RESOLVER_QUERY message counts"
ret=0
[ $rq1 -eq 0 ] || {
        echo "ns1 $rq1 expected 0" ; ret=1
}
[ $rq2 -eq 0 ] || {
        echo "ns2 $rq2 expected 0" ; ret=1
}
[ $rq3 -eq 4 ] || {
        echo "ns3 $rq3 expected 4" ; ret=1
}
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:checking RESOLVER_RESPONSE message counts"
ret=0
[ $rr1 -eq 0 ] || {
        echo "ns1 $rr1 expected 0" ; ret=1
}
[ $rr2 -eq 0 ] || {
        echo "ns2 $rr2 expected 0" ; ret=1
}
[ $rr3 -eq 4 ] || {
        echo "ns3 $rr3 expected 4" ; ret=1
}
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
exit $status
