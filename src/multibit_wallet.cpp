#include <fc/filesystem.hpp>
#include <fc/exception/exception.hpp>
#include <fc/io/datastream.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/locale.hpp>
#include <fc/crypto/aes.hpp>
#include <bts/pts_address.hpp>
#include <fc/log/logger.hpp>
#include <fc/crypto/scrypt.hpp>

#include "multibit.pb.h"
#include <iostream>

namespace bts
{
      std::vector<fc::ecc::private_key> import_multibit_wallet( const fc::path& wallet_dat, const std::string& passphrase )
      {
          if (!fc::exists(wallet_dat))
              return std::vector<fc::ecc::private_key>();
              
          std::basic_string<char16_t> passphrase16 = boost::locale::conv::utf_to_utf<char16_t>(passphrase);              

          uint8_t passphrase8[passphrase16.size()*2];           
          for (uint8_t i = 0; i < passphrase16.size(); i++)           
          {               
              passphrase8[2*i] = ((uint8_t*)passphrase16.data())[2*i+1];               
              passphrase8[2*i+1] = ((uint8_t*)passphrase16.data())[2*i];           
          }

          boost::filesystem::ifstream is_wallet(wallet_dat);

          wallet::Wallet pb_wallet;
          pb_wallet.ParseFromIstream(&is_wallet);

          std::string salt;
          if (pb_wallet.encryption_type() == pb_wallet.ENCRYPTED_SCRYPT_AES)
              salt = pb_wallet.encryption_parameters().salt();

          std::vector<fc::ecc::private_key> keyReturn;
          for (int i = 0; i < pb_wallet.key_size(); i++)
          {
              std::string pkey_data;
			  if (pb_wallet.encryption_type() == pb_wallet.UNENCRYPTED)
                  pkey_data = pb_wallet.key(i).private_key();

              else if (pb_wallet.encryption_type() == pb_wallet.ENCRYPTED_SCRYPT_AES)
              {
                  pkey_data = pb_wallet.key(i).encrypted_private_key().encrypted_private_key();
                  std::string iv = pb_wallet.key(i).encrypted_private_key().initialisation_vector();

                  unsigned char scrypt_key[48];
                  int ret = fc::crypto_scrypt(passphrase8, passphrase16.size()*2,
												(uint8_t*)salt.c_str(), salt.size(),
												pb_wallet.encryption_parameters().n(),
												pb_wallet.encryption_parameters().r(),
												pb_wallet.encryption_parameters().p(),

												scrypt_key, 48);
                  
				  if (ret != 0)
                  {
                      FC_LOG_MESSAGE( warn, "scrypt key derivation for key {nkey} failed.", ( "nkey", i ) );
                      continue;
                  }

                  try
                  {
                      unsigned char output[48];
                      int klen = fc::aes_decrypt((unsigned char*)pkey_data.c_str(), pkey_data.size(), scrypt_key, (unsigned char*)iv.c_str(), output);
                      if (!klen)
                      {
                          FC_LOG_MESSAGE( warn, "aes decryption for key {nkey} failed.", ( "nkey", i ) );
                          continue;
                      }

                      pkey_data.assign((char*)output, klen);
                  }
                  catch( fc::exception& e )
                  {
                      ilog( "something went wrong while decrypting! {msg}", ("msg", e.to_string() + ", " + e.to_detail_string()) );
                  }
              }

              else
                  continue;

              fc::datastream<const char*> stream(pkey_data.c_str(), pkey_data.size());
              fc::sha256 bits;
              stream >> bits;

              keyReturn.push_back(fc::ecc::private_key::regenerate(bits));
          }

          return keyReturn;
      }
}
