#!/bin/bash
CLIENT="../target/release/encointer-client 127.0.0.1:9979 "

# generate and pre-fund accounts
account1=$($CLIENT new_account)
echo $account1
$CLIENT fund_account $account1

account2=$($CLIENT new_account)
echo $account2
$CLIENT fund_account $account2

account3=$($CLIENT new_account)
echo $account3
$CLIENT fund_account $account3

phase=$($CLIENT get_phase)
echo "phase is $phase"
if [ "$phase" == "REGISTERING" ]; then
   echo "that's fine"
elif [ "$phase" == "ASSIGNING" ]; then
   echo "need to advance"
   $CLIENT next_phase   
   $CLIENT next_phase
elif [ "$phase" == "WITNESSING" ]; then
   echo "need to advance"
   $CLIENT next_phase   
fi
phase=$($CLIENT get_phase)
echo "phase is now: $phase"

echo "*** registering new accounts for meetup"
# assuming we are in "REGISTERING" phase
$CLIENT register_participant $account1
$CLIENT register_participant $account2
$CLIENT register_participant $account3

# list registry
$CLIENT list_participant_registry

$CLIENT next_phase
# should now be ASSIGNING

$CLIENT list_meetup_registry

$CLIENT next_phase
# should now be WITNESSING

echo "*** start meetup"
claim1=$($CLIENT new_claim $account1 3)
claim2=$($CLIENT new_claim $account2 3)
claim3=$($CLIENT new_claim $account3 3)

echo "*** sign each others claims"
witness1_2=$($CLIENT sign_claim $account1 $claim2)
witness1_3=$($CLIENT sign_claim $account1 $claim3)

witness2_1=$($CLIENT sign_claim $account2 $claim1)
witness2_3=$($CLIENT sign_claim $account2 $claim3)

witness3_1=$($CLIENT sign_claim $account3 $claim1)
witness3_2=$($CLIENT sign_claim $account3 $claim2)

echo "*** send witnesses to chain"
$CLIENT register_witnesses $account1 $witness2_1 $witness3_1
$CLIENT register_witnesses $account2 $witness1_2 $witness3_2
$CLIENT register_witnesses $account3 $witness1_3 $witness2_3

$CLIENT list_witnesses_registry

echo "*** balances before reward round"
$CLIENT get_balance $account1
$CLIENT get_balance $account2
$CLIENT get_balance $account3
echo "*** move phase to issue rewards"
$CLIENT next_phase
echo "*** balances after reward round"
$CLIENT get_balance $account1
$CLIENT get_balance $account2
$CLIENT get_balance $account3
