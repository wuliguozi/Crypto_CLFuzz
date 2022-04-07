### Algorithm and their configurations

Algorithms and their configurations(test modes) are all the test targets of CLFuzz. An algorithm may have various modes that holds different requirements on input data. An example of algorithm and configuration:

* Algorithm : Block Encryption
* Configuration:  AES_128_CBC, AES_128_CCM, AES_128_CFB, AES_128_ECB, AES_192_CBC, AES_192_CCM, AES_192_CFB, AES_192_ECB, DES_CBC, DES_CFB, DES_ECB ...

### Interfaces for function and querying

Take symmetric encryption algorithm for example, interfaces for this function provided by OpenSSL includes: 

```
int EVP_EncryptInit_exint EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
                                  const EVP_CIPHER *cipher, ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl);
```

Interfaces for querying the requirements on key length, iv length and block size are:

```
int EVP_CIPHER_get_key_length(const EVP_CIPHER *cipher);
int EVP_CIPHER_get_iv_length(const EVP_CIPHER *cipher);
int EVP_CIPHER_get_block_size(const EVP_CIPHER *cipher);
```

### Limitation of query interfaces

Some requirements on input data lack the corresponding query interfaces. For example, when doing key derivation algorithm with mode crypto_pwhash_ALG_ARGON2I13 in library libsodium, it requires the parameter **opslimit** to be more than 3. 

```
int crypto_pwhash(unsigned char * const out, unsigned long long outlen,
                  const char * const passwd, unsigned long long passwdlen,
                  const unsigned char * const salt,
                  unsigned long long opslimit, size_t memlimit, int alg)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));
```

However, there are no API for users to get this requirement, so CLFuzz would miss it.

### Example of adding new library

The class module of each tested library:

```
class Module {
    public:
        const std::string name;
        const uint64_t ID;

        Module(const std::string name) :
            name(name),
            ID(fuzzing::datasource::ID( ("Cryptofuzz/Module/" + name).c_str()))
        { }

        virtual ~Module() { }

        virtual std::optional<component::Digest> OpDigest(operation::Digest& op) {
            (void)op;
            return ret;
        }
        virtual std::optional<component::MAC> OpHMAC(operation::HMAC& op) {
            (void)op;
            return std::nullopt;
        }
        virtual std::optional<component::Ciphertext> OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
            (void)op;
            return std::nullopt;
        }
        ...
}
```

To add a new library, we initiate a new object of class Module, and implement the virtual functions supported by the new library.