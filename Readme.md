Testing the code:

Download: git clone https://github.com/AlexanderSenf/crypt4gh_development.git

cd crypt4gh_development

Build: ant package-for-store

There are two key pairs included, for testing "john" and "plain" (poth are private/public key pairs.

Encryption, for target user john:

java -jar store/crypt4gh_x.jar -e -f testfile.txt -o testfile.c4gh.john.txt -rk  plain.sec -uk john.pub

Decryption, as user john:

java -jar store/crypt4gh_x.jar -d -f testfile.c4gh.john.txt -o testfile.john.txt -rk john.sec

