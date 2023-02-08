/*
    BLAKE3-SIV.NET: A .NET implementation of Taylor Campbell's BLAKE3-SIV.
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

using System.Buffers.Binary;
using System.Security.Cryptography;
using Blake3;

namespace Blake3SivDotNet;

public static class Blake3Siv
{
    public const int KeySize = 32;
    public const int TagSize = 32;
    
    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length != plaintext.Length + TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length + TagSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }
        
        Span<byte> tag = ciphertext[^TagSize..];
        ComputeTag(tag, plaintext, key, associatedData);
        
        Span<byte> keystream = ciphertext[..^TagSize];
        ComputeKeystream(keystream, tag, key);
        
        Xor(keystream, plaintext);
    }
    
    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length < TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be at least {TagSize} bytes long."); }
        if (plaintext.Length != ciphertext.Length - TagSize) { throw new ArgumentOutOfRangeException(nameof(plaintext), plaintext.Length, $"{nameof(plaintext)} must be {ciphertext.Length - TagSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }
        
        ReadOnlySpan<byte> tag = ciphertext[^TagSize..];
        ComputeKeystream(plaintext, tag, key);
        
        Xor(plaintext, ciphertext);
        
        Span<byte> computedTag = stackalloc byte[TagSize];
        ComputeTag(computedTag, plaintext, key, associatedData);
        
        if (CryptographicOperations.FixedTimeEquals(tag, computedTag)) {
            return;
        }
        CryptographicOperations.ZeroMemory(plaintext);
        throw new CryptographicException();
    }
    
    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData)
    {
        Span<byte> associatedDataLength = stackalloc byte[sizeof(ulong)], plaintextLength = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(associatedDataLength, (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(plaintextLength, (ulong)plaintext.Length);
        
        using var blake3 = Hasher.NewKeyed(key);
        if (associatedData.Length > 0) {
            blake3.UpdateWithJoin(associatedData);
        }
        blake3.UpdateWithJoin(plaintext);
        blake3.Update(associatedDataLength);
        blake3.Update(plaintextLength);
        blake3.Update(stackalloc byte[] { 0x00 });
        blake3.Finalize(tag);
    }
    
    private static void ComputeKeystream(Span<byte> keystream, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> key)
    {
        using var blake3 = Hasher.NewKeyed(key);
        blake3.Update(tag);
        blake3.Update(stackalloc byte[] { 0x01 });
        blake3.Finalize(keystream);
    }
    
    private static unsafe void Xor(Span<byte> keystream, ReadOnlySpan<byte> message)
    {
        int chunks = keystream.Length / 8;
        fixed (byte* keystreamPtr = keystream, messagePtr = message)
        {
            long* k = (long*)keystreamPtr, m = (long*)messagePtr;
            for (int i = 0; i < chunks; i++)
            {
                *k ^= *m;
                k++;
                m++;
            }
        }
        for (int i = chunks * 8; i < keystream.Length; i++)
        {
            keystream[i] ^= message[i];
        }
    }
}