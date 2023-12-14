#!/bin/sh
# This file is in the public domain.
trap "gnunet-arm -e -c test_gns_lookup.conf" INT

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --version 1> /dev/null
if test $? != 0
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX"
	exit 77
fi

rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`
which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 30"
TEST_A="139.134.54.9"
MY_EGO="myego"
LABEL="testsbox"
PREFIX1="_name"
PREFIX2="__"
PREFIX3="_a_b_c_d_e_f_g_h_i_j_k_l_m_n_o_p_q_r_s_t_u_v_w_x_y_z_"
PREFIX4="abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz._abc"
PREFIX5="abc.abc._abc.abc"
PREFIX6="abc.abc._abc.abc._abc"
PREFIX7="abc.abc._abc.abc._abc.abc"
PREFIX8="_at"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t SBOX -V "$PREFIX1 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t SBOX -V "$PREFIX2 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t SBOX -V "$PREFIX3 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t SBOX -V "$PREFIX4 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t SBOX -V "$PREFIX5 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t SBOX -V "$PREFIX6 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t SBOX -V "$PREFIX7 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n '@' -t SBOX -V "$PREFIX8 1 $TEST_A" -e never -c test_gns_lookup.conf
sleep 0.5
RES_A1=`$DO_TIMEOUT gnunet-gns --raw -u $PREFIX1.$LABEL.$MY_EGO -t A -c test_gns_lookup.conf`
RES_A2=`$DO_TIMEOUT gnunet-gns --raw -u $PREFIX2.$LABEL.$MY_EGO -t A -c test_gns_lookup.conf`
RES_A3=`$DO_TIMEOUT gnunet-gns --raw -u $PREFIX3.$LABEL.$MY_EGO -t A -c test_gns_lookup.conf`
RES_A4=`$DO_TIMEOUT gnunet-gns --raw -u $PREFIX4.$LABEL.$MY_EGO -t A -c test_gns_lookup.conf`
RES_A5=`$DO_TIMEOUT gnunet-gns --raw -u $PREFIX5.$LABEL.$MY_EGO -t A -c test_gns_lookup.conf`
RES_A6=`$DO_TIMEOUT gnunet-gns --raw -u $PREFIX6.$LABEL.$MY_EGO -t A -c test_gns_lookup.conf`
RES_A7=`$DO_TIMEOUT gnunet-gns --raw -u $PREFIX7.$LABEL.$MY_EGO -t A -c test_gns_lookup.conf`
RES_A8=`$DO_TIMEOUT gnunet-gns --raw -u $PREFIX8.$MY_EGO -t A -c test_gns_lookup.conf`
gnunet-namestore -z $MY_EGO -d -n $LABEL -t SBOX -V "$PREFIX1 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -z $MY_EGO -d -n $LABEL -t SBOX -V "$PREFIX2 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -z $MY_EGO -d -n $LABEL -t SBOX -V "$PREFIX3 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -z $MY_EGO -d -n $LABEL -t SBOX -V "$PREFIX4 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -z $MY_EGO -d -n $LABEL -t SBOX -V "$PREFIX5 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -z $MY_EGO -d -n $LABEL -t SBOX -V "$PREFIX6 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -z $MY_EGO -d -n $LABEL -t SBOX -V "$PREFIX7 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -z $MY_EGO -d -n '@' -t SBOX -V "$PREFIX8 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

if [ "$RES_A1" = "$TEST_A" ]
then
  exit 0
else
  echo "Failed to resolve to proper A, got '$RES_A1'."
  exit 1
fi

if [ "$RES_A2" = "$TEST_A" ]
then
  exit 0
else
  echo "Failed to resolve to proper A, got '$RES_A2'."
  exit 1
fi

if [ "$RES_A3" = "$TEST_A" ]
then
  exit 0
else
  echo "Failed to resolve to proper A, got '$RES_A3'."
  exit 1
fi

if [ "$RES_A4" = "$TEST_A" ]
then
  exit 0
else
  echo "Failed to resolve to proper A, got '$RES_A4'."
  exit 1
fi

if [ "$RES_A5" = "$TEST_A" ]
then
  echo "Should have failed to resolve to proper A, got '$RES_A5' anyway."
  exit 1
else
  exit 0
fi

if [ "$RES_A6" = "$TEST_A" ]
then
  exit 0
else
  echo "Failed to resolve to proper A, got '$RES_A6'."
  exit 1
fi

if [ "$RES_A7" = "$TEST_A" ]
then
  echo "Should have failed to resolve to proper A, got '$RES_A7' anyway."
  exit 1
else
  exit 0
fi

if [ "$RES_A8" = "$TEST_A" ]
then
  exit 0
else
  echo "Failed to resolve to proper A, got '$RES_A8'."
  exit 1
fi
