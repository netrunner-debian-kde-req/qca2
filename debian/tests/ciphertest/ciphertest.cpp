/*
 Copyright (C) 2003 Justin Karneges <justin@affinix.com>
 Copyright (C) 2005-2006 Brad Hards <bradh@frogmouth.net>
 Copyright (C) 2015 Felix Geyer <fgeyer@debian.org>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <QCoreApplication>
#include <QtCrypto>

int main(int argc, char **argv)
{
    QCA::Initializer init;

    QCoreApplication app(argc, argv);

    QCA::SecureArray plainText(QByteArray::fromHex("6bc1bee22e409f96e93d7e117393172a"));

    if (!QCA::isSupported("aes128-cbc-pkcs7")) {
        qWarning("AES128-CBC not supported");
        return 1;
    }

    QCA::SymmetricKey key(QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c"));

    QCA::InitializationVector iv(QByteArray::fromHex("000102030405060708090A0B0C0D0E0F"));;

    QCA::Cipher cipher(QString("aes128"), QCA::Cipher::CBC,
                       QCA::Cipher::DefaultPadding,
                       QCA::Encode,
                       key, iv);

    QCA::SecureArray cipherText = cipher.update(plainText);
    QString cipherTextHex = QCA::arrayToHex(cipherText.toByteArray());
    QString expectedHex("7649abac8119b246cee98e9b12e9197d");

    if (!cipher.ok()) {
        qWarning("update() failed");
        return 1;
    }

    cipher.final();
    if (!cipher.ok()) {
        qWarning("final() failed");
        return 1;
    }

    if (cipherTextHex != expectedHex) {
        qWarning("Error: result: %s, expected: %s", qPrintable(cipherTextHex),
                 qPrintable(expectedHex));
        return 1;
    }

    return 0;
}
