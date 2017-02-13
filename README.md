I sought a cipher block method with these properties:

1.  The ciphertext is the same size as the plaintext.

2.  Every bit of the ciphertext depends on every bit of the plaintext.

Most methods use an initialization vector (IV), which expands the
message somewhat, and thus cannot be used to encrypt “in-place”.
You can run algorithms such as CBC with a zero IV, but this will leak
identical prefixes; that is, a change in the plaintext only affects
its block and succeeding ones in the ciphertext.

Disk encryption methods do encrypt in-place, but use context data
such as the sector number in the cipher, and so still use outside bits.

Properties such a method will have:

1.  Identical plaintexts will produce identical ciphertexts.  Most block
methods seek to avoid this, but that cannot be done without expanding
the size.

2.  Encryption requires two passes.  This is necessary because the
first ciphertext bit must depend on every bit of the plaintext.
Thus we cannot do stream encryption.  However, it is possible to do
stream decryption, as we shall see.

I attempted to find an existing solution to this problem but did not,
so I developed my own.  It is a pretty natural solution and so may
have been done before.

Assume you have a plaintext of _n_ blocks.  The first _n_-1 are
cryptographically hashed to produce a block (this implementation
uses SHA-256 as the hash).  This block is then used as an IV, and
all _n_ blocks are encrypted in reverse, starting with the last,
using a suitable cipher block method such as CBC (or CFB), which is
self-correcting, and your favorite block cipher such as AES.

For decryption, one uses the property of CBC that knowing the previous
ciphertext block is enough can be used with the key to decrypt the
current one.  Since the encryption was in reverse, that means stream
decryption of the first _n_-1 blocks can be done with one-block
lookahead.  To decrypt the last block one computes the hash of all
previous ones (which can be done cumulatively) to recover the IV.

This method has some random-access and self-correcting properties,
but it is not designed for those, and in particular the last block
cannot be decrypted without having the rest complete and intact.
There is probably a theorem that this is a necessary property.

The above assumes the plaintext length is a multiple of the block size.
A variant of ciphertext stealing can be used to extend the method
to any size larger than the block size.  An extra encryption step is
used to assure full bit dependency, and the bits are ordered so that
no more than one-block lookahead is ever needed, that is, one does
not need to check further to see if the stream is about to end.

This Haskell code is a proof of concept of this technique.  It uses
the packages `base-prelude`, `cryptohash-sha256`, and `cipher-aes128`.
The implementation is meant only to illustrate and is not the most
efficient; the encryption in particular could be much improved with
byte operations.

Example usage:

```haskell
$ ghci bijecrypt.hs
*Main> :set -XOverloadedStrings
*Main> let msg = "Once upon a midnight dreary, while I pondered, weak and weary"
*Main> BS.length msg
61
*Main> let enc = encrypt "test" msg
*Main> BS.length enc
61
*Main> decrypt "test" enc
"Once upon a midnight dreary, while I pondered, weak and weary"
```

You can verify the stream decryption property, that it does not need
to look at more than the next block:

```haskell
*Main> BL.take 32 $ decryptLazy "test" $ BL.fromStrict (BS.take 48 enc) <> undefined
"Once upon a midnight dreary, whi"
```

One can also see the extent and limitation of error recovery:

```haskell
*Main> decrypt "test" $ BS.cons 0 $ BS.tail enc
"\154\166u=\151\172\128\205\190R\186\207<\205V\245ight dreary, whi\131.\238\176.X\236v\129\249q\217%-,\140eak and weary"
```

A few notes:

1.  The length of the plaintext must be at least one block size,
here 16 bytes.  I have an extension for smaller blocks, although
security will be naturally much less for a small number of bytes.

2.  One can obscure identical plaintexts by adding a number of nonce
bytes appropriate to your application, perhaps fewer than a full
block's worth, which is what an IV would add.


