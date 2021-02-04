/*
 *
 * Copyright 2018 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <string>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/aead_cryptor.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/trusted_application.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "quickstart/demo.pb.h"
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <fstream>
#include <openssl/md5.h>
#include "openssl/sha.h"



#define KEY_LENGTH 2048 // RSA Key length
#define PUB_KEY_FILE "pubkey.pem" // RSA public key path
#define PRI_KEY_FILE "prikey.pem" // RSA private key path



namespace asylo {
namespace {

// Dummy 128-bit AES key.
constexpr uint8_t kAesKey128[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                  0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
                                  0x12, 0x13, 0x14, 0x15};
inline bool file_exists (const std::string& name) {
  struct stat buffer;
  return (stat (name.c_str(), &buffer) == 0);
}
/*
 @brief: signs and verifies a givens string
 @para: data, the string to be signed and verified
**/
void doSign(std::string data)
{
    RSA * pubkey=NULL;
    RSA * prikey=NULL;
    FILE *pbkey_from_file = fopen(PUB_KEY_FILE,"r");
    FILE *pkey_from_file = fopen(PRI_KEY_FILE,"r");
    unsigned char digest[SHA512_DIGEST_LENGTH];
    unsigned char sign[512];
    unsigned int signLen;
    int     ret;
    // read public key from file for verifying signature
    pubkey = PEM_read_RSAPublicKey(pbkey_from_file,&pubkey,NULL,NULL);
    // read private key from file for signing
    prikey = PEM_read_RSAPrivateKey(pkey_from_file,&prikey,NULL,NULL);

    // caclculate the hash of the messsage to be signed
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx,(const char *) data.c_str(), strlen(data.c_str()));
    SHA512_Final(digest, &ctx);

    unsigned char mdString[SHA512_DIGEST_LENGTH*2+1];
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        sprintf((char *) &mdString[i*2], "%02x", (unsigned int)digest[i]);

    /* Sign the hash*/
    ret = RSA_sign(NID_sha512 , mdString, SHA512_DIGEST_LENGTH, sign,
                   &signLen, prikey);
    //printf("Signature length = %d\n", signLen);
    printf("RSA_sign: %s\n", (ret == 1) ? "OK" : "NG");

    /* Verify signature*/
    ret = RSA_verify(NID_sha512, mdString, SHA512_DIGEST_LENGTH, sign,
                     signLen, pubkey);
    printf("RSA_Verify: %s\n", (ret == 1) ? "true" : "false");

    fclose(pbkey_from_file);
    fclose(pkey_from_file);
}

/*
 @brief: private key encryption
 @para: clear_text -[i] The clear text that needs to be encrypted
                   pri_key -[i] private key
 @return: Encrypted data
**/
std::string RsaPriEncrypt(const std::string &clear_text, std::string &pri_key)
{
    std::string encrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pri_key.c_str(), -1);
    RSA* rsa = RSA_new();
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        BIO_free_all(keybio);
        return std::string("");
    }

     // Get the maximum length of data that RSA can process at a time
    int len = RSA_size(rsa);

     // Apply for memory: store encrypted ciphertext data
    char *text = new char[len + 1];
    memset(text, 0, len + 1);

     // Encrypt the data with a private key (the return value is the length of the encrypted data)
    int ret = RSA_private_encrypt(clear_text.length(), (const unsigned char*)clear_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0) {
        encrypt_text = std::string(text, ret);
    }

     // release memory
    free(text);
    BIO_free_all(keybio);
    RSA_free(rsa);

    return encrypt_text;
}
/*
 @brief: public key decryption
 @para: cipher_text -[i] encrypted ciphertext
                   pub_key -[i] public key
 @return: decrypted data
**/
std::string RsaPubDecrypt(const std::string & cipher_text, const std::string & pub_key)
{
    std::string decrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pub_key.c_str(), -1);
    RSA *rsa = RSA_new();

     // Note--------Use the public key in the first format for decryption
    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
     // Note--------Use the public key in the second format for decryption (we use this format as an example)
    //rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
         unsigned long err = ERR_get_error(); //Get the error number
        char err_msg[1024] = { 0 };
                 ERR_error_string(err, err_msg); // Format: error:errId: library: function: reason
        printf("err msg: err:%ld, msg:%s\n", err, err_msg);
        BIO_free_all(keybio);
        return decrypt_text;
    }

    int len = RSA_size(rsa);
    char *text = new char[len + 1];
    memset(text, 0, len + 1);
     // Decrypt the ciphertext
    int ret = RSA_public_decrypt(cipher_text.length(), (const unsigned char*)cipher_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0) {
        decrypt_text.append(std::string(text, ret));
    }

     // release memory
    delete text;
    BIO_free_all(keybio);
    RSA_free(rsa);

    return decrypt_text;
}

/*
 Manufacturing key pair: private key and public key
**/
void GenerateRSAKey(std::string & out_pub_key, std::string & out_pri_key)
{
    size_t pri_len = 0; // Private key length
    size_t pub_len = 0; // public key length
    char *pri_key = nullptr; // private key
    char *pub_key = nullptr; // public key
    RSA *keypair = NULL;
    BIGNUM *bne = NULL;
    int ret = 0;
    unsigned long e = RSA_F4;


     // Generate key pair
    //RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);
    bne = BN_new();
    ret = BN_set_word(bne, e);
    keypair = RSA_new();
    ret = RSA_generate_key_ex(keypair, KEY_LENGTH, bne, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

         // Generate private key
    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
         // Note------Generate the public key in the first format
    PEM_write_bio_RSAPublicKey(pub, keypair);
         // Note------Generate the public key in the second format (this is used in the code here)
    //PEM_write_bio_RSA_PUBKEY(pub, keypair);

     // Get the length
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

     // The key pair reads the string
    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    out_pub_key = pub_key;
    out_pri_key = pri_key;

     // Write the public key to the file
    std::ofstream pub_file(PUB_KEY_FILE, std::ios::out);
    if (!pub_file.is_open())
    {
        perror("pub key file open fail:");
        return;
    }
    pub_file << pub_key;
    pub_file.close();

     // write private key to file
    std::ofstream pri_file(PRI_KEY_FILE, std::ios::out);
    if (!pri_file.is_open())
    {
        perror("pri key file open fail:");
        return;
    }
    pri_file << pri_key;
    pri_file.close();

     // release memory
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);

    free(pri_key);
    free(pub_key);
}

std::string Md5Sum(std::string input) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    char string[] = "";

    strcpy( string, input.c_str() );
    MD5((unsigned char*)&string, strlen(string), (unsigned char*)&digest);

    char mdString[33];

    for(int i = 0; i < 16; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
    std::string md_string = std::string(mdString);
    return md_string;

}

std::string Sha1Sum(std::string input) {

    unsigned char digest[SHA_DIGEST_LENGTH];

    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx,(const char *) input.c_str(), strlen(input.c_str()));
    SHA1_Final(digest, &ctx);

    char mdString[SHA_DIGEST_LENGTH*2+1];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

    std::string sha_string = std::string(mdString);
    return sha_string;

}

std::string Sha2Sum(std::string input) {
    unsigned char digest[SHA512_DIGEST_LENGTH];

    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx,(const char *) input.c_str(), strlen(input.c_str()));
    SHA512_Final(digest, &ctx);

    char mdString[SHA512_DIGEST_LENGTH*2+1];
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

    std::string sha512_string = std::string(mdString);
    return sha512_string;
//    printf("SHA512 digest: %s\n", mdString);

}

// Helper function that adapts absl::BytesToHexString, allowing it to be used
// with ByteContainerView.
std::string BytesToHexString(ByteContainerView bytes) {
  return absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char *>(bytes.data()), bytes.size()));
}

// Encrypts a message against `kAesKey128` and returns a 12-byte nonce followed
// by authenticated ciphertext, encoded as a hex string.
const StatusOr<std::string> EncryptMessage(const std::string &message) {
  std::unique_ptr<AeadCryptor> cryptor;
  ASYLO_ASSIGN_OR_RETURN(cryptor,
                         AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));

  std::vector<uint8_t> additional_authenticated_data;
  std::vector<uint8_t> nonce(cryptor->NonceSize());
  std::vector<uint8_t> ciphertext(message.size() + cryptor->MaxSealOverhead());
  size_t ciphertext_size;

  ASYLO_RETURN_IF_ERROR(cryptor->Seal(
      message, additional_authenticated_data, absl::MakeSpan(nonce),
      absl::MakeSpan(ciphertext), &ciphertext_size));

  return absl::StrCat(BytesToHexString(nonce), BytesToHexString(ciphertext));
}

// Decrypts a message using `kAesKey128`. Expects `nonce_and_ciphertext` to be
// encoded as a hex string, and lead with a 12-byte nonce. Intended to be
// used by the reader for completing the exercise.
const StatusOr<CleansingString> DecryptMessage(
    const std::string &nonce_and_ciphertext) {
  std::string input_bytes = absl::HexStringToBytes(nonce_and_ciphertext);

  std::unique_ptr<AeadCryptor> cryptor;
  ASYLO_ASSIGN_OR_RETURN(cryptor,
                         AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));

  if (input_bytes.size() < cryptor->NonceSize()) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrCat("Input too short: expected at least ",
                     cryptor->NonceSize(), " bytes, got ", input_bytes.size()));
  }

  std::vector<uint8_t> additional_authenticated_data;
  std::vector<uint8_t> nonce = {input_bytes.begin(),
                                input_bytes.begin() + cryptor->NonceSize()};
  std::vector<uint8_t> ciphertext = {input_bytes.begin() + cryptor->NonceSize(),
                                     input_bytes.end()};

  // The plaintext is always smaller than the ciphertext, so use
  // `ciphertext.size()` as an upper bound on the plaintext buffer size.
  CleansingVector<uint8_t> plaintext(ciphertext.size());
  size_t plaintext_size;

  ASYLO_RETURN_IF_ERROR(cryptor->Open(ciphertext, additional_authenticated_data,
                                      nonce, absl::MakeSpan(plaintext),
                                      &plaintext_size));

  return CleansingString(plaintext.begin(), plaintext.end());
}

}  // namespace

class EnclaveDemo : public TrustedApplication {
 public:
  EnclaveDemo() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    std::string user_message = GetEnclaveUserMessage(input);
    std::string pubkey,prikey;

    std::string encrypt_text;
    std::string decrypt_text;

    switch (GetEnclaveUserAction(input)) {
      case guide::asylo::Demo::ENCRYPT: {
        std::string result;
        ASYLO_ASSIGN_OR_RETURN(result, EncryptMessage(user_message));
        SetEnclaveOutputMessage(output, result);
        break;
      }
      case guide::asylo::Demo::MD5SUM: {
        SetEnclaveOutputMessage(output, Md5Sum(user_message));
        break;
      }
      case guide::asylo::Demo::SHA1SUM: {
        SetEnclaveOutputMessage(output, Sha1Sum(user_message));
        break;
      }
      case guide::asylo::Demo::SHA512SUM: {
        SetEnclaveOutputMessage(output, Sha2Sum(user_message));
        break;
      }
      case guide::asylo::Demo::CREATERSA: {
        GenerateRSAKey(pubkey,prikey);
        encrypt_text = RsaPriEncrypt((user_message), prikey);
        doSign(encrypt_text);
        decrypt_text = RsaPubDecrypt(encrypt_text, pubkey);
        SetEnclaveOutputMessage(output, decrypt_text);
        break;
      }
      case guide::asylo::Demo::DECRYPT: {
        CleansingString result;
        ASYLO_ASSIGN_OR_RETURN(result, DecryptMessage(user_message));
        SetEnclaveOutputMessage(output, result);
        break;
      }
      default:
        return Status(error::GoogleError::INVALID_ARGUMENT,
                      "Action unspecified");
    }

    return Status::OkStatus();
  }

  // Retrieves user message from |input|.
  const std::string GetEnclaveUserMessage(const EnclaveInput &input) {
    return input.GetExtension(guide::asylo::quickstart_input).value();
  }
  // Retrieves user action from |input|.
  guide::asylo::Demo::Action GetEnclaveUserAction(const EnclaveInput &input) {
    return input.GetExtension(guide::asylo::quickstart_input).action();
  }
  // Populates |enclave_output|->value() with |output_message|. Intended to be
  // used by the reader for completing the exercise.
  void SetEnclaveOutputMessage(EnclaveOutput *enclave_output,
                               absl::string_view output_message) {
    guide::asylo::Demo *output =
        enclave_output->MutableExtension(guide::asylo::quickstart_output);
    output->set_value(std::string(output_message));
  }
};

//  // Populates |enclave_output|->value() with |output_message|. Intended to be
//  // used by the reader for completing the exercise.
//  void SetEnclaveOutputMessage(EnclaveOutput *enclave_output,
//                               const std::string &output_message) {
//    guide::asylo::Demo *output =
//        enclave_output->MutableExtension(guide::asylo::quickstart_output);
//    output->set_value(output_message);
//  }
//};

TrustedApplication *BuildTrustedApplication() { return new EnclaveDemo; }

}  // namespace asylo
