using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Blake3SivDotNet;

namespace Blake3SivDotNetTests;

[TestClass]
public class Blake3SivTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "b609cc0254748bf676c3b5a581a6eb37be9aa01fac52a50b636332a18612ea1e3c4564210d6bdf8bbb8e5dd8599acf413e6f1b7ae3beebf2076e09b4ec6fdadadc24302cb734d98ca29bfbb3c6c386d05e6bd4f82e3bf80b3d7f783d83718c382ec6b527353704e752014c6da910b34fe5694aa36539e3cfa1fa56908cd3455fcb46d4085e2429d7fea88e8d8bf49c1a7e88",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }
    
    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { Blake3Siv.TagSize + 1, 0, Blake3Siv.KeySize, 1 };
        yield return new object[] { Blake3Siv.TagSize - 1, 0, Blake3Siv.KeySize, 1 };
        yield return new object[] { Blake3Siv.TagSize, 0, Blake3Siv.KeySize + 1, 1 };
        yield return new object[] { Blake3Siv.TagSize, 0, Blake3Siv.KeySize - 1, 1 };
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string key, string associatedData)
    {
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);
        Span<byte> c = stackalloc byte[p.Length + Blake3Siv.TagSize];
        
        Blake3Siv.Encrypt(c, p, k, a);
        
        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var k = new byte[keySize];
        var a = new byte[associatedDataSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Blake3Siv.Encrypt(c, p, k, a));
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string key, string associatedData)
    {
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);
        Span<byte> p = stackalloc byte[c.Length - Blake3Siv.TagSize];
        
        Blake3Siv.Decrypt(p, c, k, a);
        
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string key, string associatedData)
    {
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };
        var p = new byte[parameters[0].Length - Blake3Siv.TagSize];
        
        foreach (var param in parameters) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => Blake3Siv.Decrypt(p, parameters[0], parameters[1], parameters[2]));
            Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
            param[0]--;
        }
    }
    
    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var k = new byte[keySize];
        var a = new byte[associatedDataSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Blake3Siv.Decrypt(p, c, k, a));
    }
}