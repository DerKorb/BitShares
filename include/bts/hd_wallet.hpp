#pragma once
#include <fc/crypto/elliptic.hpp>

namespace bts {

  /**
   *  Given an extended public key you calculate the public key of all
   *  children keys, but not the coresponding private keys.  
   *
   *  @note this only works for extended private keys that use public derivation
   */
  class extended_public_key
  {
     public:
        extended_public_key();
        ~extended_public_key();

        extended_public_key( const fc::ecc::public_key& key, const fc::sha256& code );

        extended_public_key child( uint32_t c )const;

        operator fc::ecc::public_key()const { return pub_key; }

        fc::ecc::public_key pub_key;
        fc::sha256          chain_code;
  };

  class extended_private_key
  {
     public:
        extended_private_key( const fc::sha256& key, const fc::sha256& chain_code );
        extended_private_key();

        /** @param pub_derivation - if true, then extended_public_key can be used
         *      to calculate child keys, otherwise the extended_private_key is
         *      required to calculate all children.
         */
        extended_private_key child( uint32_t c, bool pub_derivation = false )const;

        operator fc::ecc::private_key()const;
        fc::ecc::public_key get_public_key()const;
       
        fc::sha256          priv_key;
        fc::sha256          chain_code;
  };

  /** 
   *  HD Wallet (Hierarchical-Deterministic Wallets) are loosly based upon 
   *  Bitcoin Improvement Proposal 0032  https://en.bitcoin.it/wiki/BIP_0032
   *
   *  Goal: For privacy, most transactions should only have one input and one
   *  output and a new address should be used for every output. In the case of
   *  change, a transaction may have 2 outputs.   After a sufficient number of
   *  single input, single output transactions occur it may be safe to combine
   *  two inputs into a single output.  
   *
   *  If you wanted to send someone 100 BTC you would normally create a single
   *  transaction with N inputs that total 100 BTC.  This transaction would leak
   *  information that there is a high probability than those N inputs all belong
   *  to the same individual and a single compromised input would then compromise
   *  all of the inputs.  
   *
   *  Using HD wallets, you would a series of N transactions each with 1 input and
   *  1 output, perhaps one of them would have 2 outputs for change.  The receiver
   *  would be able to 'group' these into a single payment by deriving all of the
   *  output addresses from a single 'transaction parent key' that is in turn
   *  derived from the account key.    Using this approach it is also possible
   *  for there to be subscription payments using a unique address for each payment.
   *
   *  An account is intended for each individual you do business with. You would
   *  give them the extended public key and for each transaction they would derive
   *  a new exended public key and then derive a unique public key for 
   *
   *  The intended use is for accounts to be created via private derivation,
   *  while trx and address children are created via public derivation.
   */
  class hd_wallet 
  {
     public:
        hd_wallet();

        /**
         *  This method will take several minutes to run and is designed to
         *  make rainbow tables difficult to calculate.
         */
        static fc::sha256     stretch_seed( const fc::sha256& seed );

        void                  set_seed( const fc::sha256& stretched_seed );
        fc::sha256            get_seed()const;

        extended_private_key  get_private_account( uint32_t i );
        extended_public_key   get_public_account( uint32_t i );

        extended_public_key   get_public_trx( uint32_t account, uint32_t trx );
        fc::ecc::public_key   get_public_trx_address( uint32_t account, uint32_t trx, uint32_t addr );

        extended_private_key  get_private_trx( uint32_t account, uint32_t trx );
        fc::ecc::private_key  get_private_trx_address( uint32_t account, uint32_t trx, uint32_t addr );

     private:
       extended_private_key  ext_priv_key;
  };



} // bts
#include <fc/reflect/reflect.hpp>
FC_REFLECT( bts::extended_public_key,  (pub_key)(chain_code)  )
FC_REFLECT( bts::extended_private_key, (priv_key)(chain_code) )
