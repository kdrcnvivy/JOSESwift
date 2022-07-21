//
//  AESGCMEncryption.swift
//  JOSESwift
//
//  Created by Kadircan Türker on 21.07.22.
//

import Foundation
import CryptoSwift
struct AESGCMEncryption {
    
    private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    private let contentEncryptionKey: Data
    
    init(contentEncryptionAlgorithm: ContentEncryptionAlgorithm, contentEncryptionKey: Data) {
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.contentEncryptionKey = contentEncryptionKey
    }
    
//    func encrypt(_ plaintext: Data, additionalAuthenticatedData: Data) throws -> ContentEncryptionContext {
//        print("AESGCMEncryption :::: encrypt ::: \(plaintext)")
//        let iv = try SecureRandom.generate(count: contentEncryptionAlgorithm.initializationVectorLength)
//
//        let keys = try contentEncryptionAlgorithm.retrieveKeys(from: contentEncryptionKey)
//        let encryptionKey = keys.encryptionKey
//
//        let gcm = GCM(iv: [UInt8](hex: iv.hexEncodedString()), mode: .detached)
//        let aes = try! AES(key: [UInt8](hex: encryptionKey.hexEncodedString()), blockMode: gcm, padding: .noPadding)
//        let ciphertext = try! aes.encrypt([UInt8](hex: plaintext.hexEncodedString()))
//        let tag = gcm.authenticationTag!
//
//        // Put together the input data for the HMAC. It consists of A || IV || E || AL.
//
//        return ContentEncryptionContext(
//            ciphertext: Data(ciphertext),
//            authenticationTag: Data(tag),
//            initializationVector: iv
//        )
//    }
//
//    func decrypt(
//        _ ciphertext: Data,
//        initializationVector: Data,
//        additionalAuthenticatedData: Data,
//        authenticationTag: Data
//    ) throws -> Data {
//        print("AESGCMEncryption :::: decrypt ::: \(ciphertext)")
//        // Check if the key length contains both HMAC key and the actual symmetric key.
//        guard contentEncryptionAlgorithm.checkKeyLength(for: contentEncryptionKey) else {
//            throw JWEError.keyLengthNotSatisfied
//        }
//        print("AESGCMEncryption :::: \(ciphertext)")
//        // Get the two keys for the HMAC and the symmetric encryption.
//        let keys = try contentEncryptionAlgorithm.retrieveKeys(from: contentEncryptionKey)
//        print("AESGCMEncryption :::: keys ::: \(keys)")
//        let decryptionKey = keys.encryptionKey
//        print("AESGCMEncryption :::: decryptionKey ::: \(decryptionKey)")
//        // Decrypt the cipher text with a symmetric decryption key, a symmetric algorithm and the initialization vector,
//        // return the plaintext if no error occured.
//        let gcm = GCM(iv:  [UInt8](hex: initializationVector.hexEncodedString()),authenticationTag: [UInt8](hex: authenticationTag.hexEncodedString()), mode: .detached)
//        let aes = try AES(key: [UInt8](hex: decryptionKey.hexEncodedString()), blockMode: gcm, padding: .noPadding)
//        let plaintext =  try aes.decrypt([UInt8](hex: ciphertext.hexEncodedString()))
//        print("AESGCMEncryption :::: plaintext ::: \(plaintext)")
//        return Data(plaintext)
//    }
    
    func encrypt(_ plaintext: Data, additionalAuthenticatedData: Data) throws -> ContentEncryptionContext {
        let iv = try SecureRandom.generate(count: contentEncryptionAlgorithm.initializationVectorLength)

        let keys = try contentEncryptionAlgorithm.retrieveKeys(from: contentEncryptionKey)
        let encryptionKey = keys.encryptionKey

        let  encryptTuple = try! CC.encryptAuth(blockMode: .gcm, algorithm:  .aes, data: plaintext, aData: additionalAuthenticatedData, key: encryptionKey, iv: iv, tagLength: 16)
        // Put together the input data for the HMAC. It consists of A || IV || E || AL.
        return ContentEncryptionContext(
            ciphertext: encryptTuple.0,
            authenticationTag: encryptTuple.1,
            initializationVector: iv
        )
    }

    func decrypt(
        _ ciphertext: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data,
        authenticationTag: Data
    ) throws -> Data {
        // Check if the key length contains both HMAC key and the actual symmetric key.
        guard contentEncryptionAlgorithm.checkKeyLength(for: contentEncryptionKey) else {
            throw JWEError.keyLengthNotSatisfied
        }
        let keys = try contentEncryptionAlgorithm.retrieveKeys(from: contentEncryptionKey)
        let decryptionKey = keys.encryptionKey
        let plaintext = try! CC.decryptAuth(blockMode: .gcm, algorithm: .aes, data: ciphertext, aData: additionalAuthenticatedData, key: decryptionKey, iv: initializationVector, tagLength: 16)
        return plaintext
    }
}


extension AESGCMEncryption: ContentEncrypter {
    func encrypt(header: JWEHeader, payload: Payload) throws -> ContentEncryptionContext {
        let plaintext = payload.data()
        let additionalAuthenticatedData = header.data().base64URLEncodedData()
        return try encrypt(plaintext, additionalAuthenticatedData: additionalAuthenticatedData)
        
    }
}

extension AESGCMEncryption: ContentDecrypter {
    func decrypt(decryptionContext: ContentDecryptionContext) throws -> Data {
        return try decrypt(
            decryptionContext.ciphertext,
            initializationVector: decryptionContext.initializationVector,
            additionalAuthenticatedData: decryptionContext.additionalAuthenticatedData,
            authenticationTag: decryptionContext.authenticationTag
        )
    }
}
