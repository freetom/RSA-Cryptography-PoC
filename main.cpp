//This is a test of RSA cryptography, developed by Bortoli Tomas.


#include <cstdlib>
#include <iostream>


#include "CryptographyRSA.h"

using namespace std;

int main(int argc, char *argv[])
{
    int data=37;
    
    cout<<"-----------------------------------------------"<<endl;
    cout<<"RSA-Cryptography PoC developed by Bortoli Tomas"<<endl;
    cout<<"-----------------------------------------------"<<endl;
    
    cout<<"This program is highly sperimental and is just a PoC of RSA Public Key Cryptography"<<endl<<endl<<endl;
    
    
    CryptographyRSA *rsa = new CryptographyRSA();
    
    rsa->createPublicKey();
    rsa->createPrivateKey();
    
    cout<<"Public Key:"<<endl<<"encoding key: "<<rsa->getPublicKey()<<endl<<"module: "<<rsa->getN()<<endl<<endl;
    cout<<"Private Key:"<<endl<<"decoding key: "<<rsa->getPrivateKey()<<endl<<"fi(module): "<<rsa->getFiN()<<endl<<endl;
    
    cout<<"Data: "<<data<<endl;
    data=rsa->encrypt(data);
    cout<<"Data encrypted: "<<data<<endl;
    data=rsa->decrypt(data);
    cout<<"Data decrypted: "<<data<<endl<<endl;
    
    return EXIT_SUCCESS;
    
}
