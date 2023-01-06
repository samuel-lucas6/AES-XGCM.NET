/*
    AES-XGCM.NET: A .NET implementation of AES-XGCM.
    Copyright (c) 2023 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using System.Security.Cryptography;

namespace AesXGcmDotNet;

public static class AesXGcm
{
    public const int KeySize = 32;
    public const int NonceSize = NonceExtensionSize + 12;
    public const int TagSize = 16;
    private const int BlockSize = 16;
    private const int NonceExtensionSize = BlockSize - 1;
    
    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length != plaintext.Length + TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length + TagSize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }
        
        Span<byte> subKey = stackalloc byte[KeySize];
        DeriveSubKey(subKey, nonce, key);

        using var gcm = new AesGcm(subKey);
        gcm.Encrypt(nonce[NonceExtensionSize..], plaintext, ciphertext[..^TagSize], ciphertext[^TagSize..], associatedData);
        CryptographicOperations.ZeroMemory(subKey);
    }

    private static void DeriveSubKey(Span<byte> subKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        Span<byte> nonceExtension = stackalloc byte[BlockSize];
        nonce[..NonceExtensionSize].CopyTo(nonceExtension);
        
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        
        nonceExtension[^1] = 0x01;
        aes.EncryptEcb(nonceExtension, subKey[..BlockSize], PaddingMode.None);
        
        nonceExtension[^1] = 0x02;
        aes.EncryptEcb(nonceExtension, subKey[BlockSize..], PaddingMode.None);
        
        CryptographicOperations.ZeroMemory(nonceExtension);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length < TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be at least {TagSize} bytes long."); }
        if (plaintext.Length != ciphertext.Length - TagSize) { throw new ArgumentOutOfRangeException(nameof(plaintext), plaintext.Length, $"{nameof(plaintext)} must be {ciphertext.Length - TagSize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }
        
        Span<byte> subKey = stackalloc byte[KeySize];
        DeriveSubKey(subKey, nonce, key);
        
        using var gcm = new AesGcm(subKey);
        gcm.Decrypt(nonce[NonceExtensionSize..], ciphertext[..^TagSize], ciphertext[^TagSize..], plaintext, associatedData);
        CryptographicOperations.ZeroMemory(subKey);
    }
}