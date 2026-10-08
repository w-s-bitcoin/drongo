package com.sparrowwallet.drongo.wallet;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.OutputDescriptor;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.*;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.Duration;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class SingleKeyWalletTest {
    // Deliberately public, nonvaluable scalar-1 vectors. Never use these keys for funds.
    private static final String COMPRESSED_WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
    private static final String UNCOMPRESSED_WIF = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf";
    private static final Map<ScriptType, String> ADDRESSES = Map.of(
            ScriptType.P2PKH, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ScriptType.P2SH_P2WPKH, "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
            ScriptType.P2WPKH, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            // Independently computed from G + tagged_hash("TapTweak", G.x) * G, BIP341/BIP350.
            ScriptType.P2TR, "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9");
    private Network originalNetwork;

    @BeforeEach
    void mainnet() {
        originalNetwork = Network.get();
        Network.set(Network.MAINNET);
    }

    @AfterEach
    void restoreNetwork() {
        Network.set(originalNetwork);
    }

    @Test
    void compressedAddressVectorsAndPublicDescriptors() throws Exception {
        ECKey key = DumpedPrivateKey.fromBase58(COMPRESSED_WIF).getKey();
        assertEquals(BigInteger.ONE, key.getPrivKey());
        for(Map.Entry<ScriptType, String> vector : ADDRESSES.entrySet()) {
            Wallet wallet = Wallet.fromSingleKey("Vector", key, vector.getKey());
            wallet.checkWallet();
            WalletNode node = wallet.getFreshNode(KeyPurpose.RECEIVE);
            assertEquals(vector.getValue(), node.getAddress().toString());
            assertEquals(List.of(KeyPurpose.RECEIVE), wallet.getWalletKeyPurposes());
            assertEquals(0, wallet.getGapLimit());
            assertEquals(1, wallet.getWalletAddresses().size());
            assertEquals(1, wallet.getWalletOutputScripts().size());
            assertNull(wallet.getKeystores().getFirst().getExtendedPublicKey());
            assertNull(wallet.getKeystores().getFirst().getKeyDerivation());
            assertFalse(wallet.containsMasterPrivateKeys());
            assertTrue(wallet.containsPrivateKeys());
            assertThrows(IllegalStateException.class, () -> wallet.addChildWallet(StandardAccount.ACCOUNT_1));

            OutputDescriptor descriptor = OutputDescriptor.getOutputDescriptor(wallet);
            String publicDescriptor = descriptor.toString(true);
            assertFalse(publicDescriptor.contains(COMPRESSED_WIF));
            assertFalse(publicDescriptor.contains("xprv"));
            assertFalse(publicDescriptor.contains("/*"));
            assertEquals(node.getOutputDescriptor(), descriptor.toString());
            OutputDescriptor parsed = OutputDescriptor.getOutputDescriptor(publicDescriptor);
            assertEquals(descriptor.toString(), parsed.toString());
            assertEquals(publicDescriptor, descriptor.copy(false).toString(true));
            assertFalse(parsed.describesMultipleAddresses());
            assertEquals(node.getAddress(), parsed.getAddress(Collections.emptyList()));
            Wallet watch = parsed.toWallet();
            watch.checkWallet();
            assertTrue(watch.isSingleKeyWallet());
            assertFalse(watch.containsPrivateKeys());
            assertEquals(node.getAddress(), watch.getFreshNode(KeyPurpose.RECEIVE).getAddress());
        }
    }

    @Test
    void uncompressedIsLegacyOnly() throws Exception {
        ECKey key = DumpedPrivateKey.fromBase58(UNCOMPRESSED_WIF).getKey();
        assertFalse(key.isCompressed());
        Wallet wallet = Wallet.fromSingleKey("Legacy", key, ScriptType.P2PKH);
        wallet.checkWallet();
        assertEquals("1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm", wallet.getFreshNode(KeyPurpose.RECEIVE).getAddress().toString());
        for(ScriptType scriptType : List.of(ScriptType.P2SH_P2WPKH, ScriptType.P2WPKH, ScriptType.P2TR, ScriptType.P2WSH)) {
            assertThrows(IllegalArgumentException.class, () -> Wallet.fromSingleKey("Invalid", key, scriptType));
        }
        String descriptor = OutputDescriptor.getOutputDescriptor(wallet).toString(true);
        assertEquals(wallet.getWalletAddresses().keySet(), OutputDescriptor.getOutputDescriptor(descriptor).toWallet().getWalletAddresses().keySet());
        wallet.setScriptType(ScriptType.P2WPKH);
        assertFalse(wallet.isValid());
    }

    @Test
    void rejectsMalformedChecksumNetworkCompressionAndScalars() {
        for(String invalid : List.of("", "not a WIF", "01".repeat(32), COMPRESSED_WIF.substring(1), COMPRESSED_WIF.substring(0, 51) + "1")) {
            assertThrows(RuntimeException.class, () -> DumpedPrivateKey.fromBase58(invalid));
        }
        assertThrows(IllegalArgumentException.class, () -> DumpedPrivateKey.fromBase58(null));
        assertThrows(IllegalArgumentException.class, () -> DumpedPrivateKey.fromBase58(Base58.encodeChecked(128, new byte[32])));
        assertThrows(IllegalArgumentException.class, () -> DumpedPrivateKey.fromBase58(Base58.encodeChecked(128, Utils.bigIntegerToBytes(ECKey.CURVE.getN(), 32))));
        assertThrows(IllegalArgumentException.class, () -> DumpedPrivateKey.fromBase58(Base58.encodeChecked(128, Utils.bigIntegerToBytes(ECKey.CURVE.getN().add(BigInteger.ONE), 32))));
        byte[] badCompression = new byte[33];
        badCompression[31] = 2;
        badCompression[32] = 2;
        assertThrows(IllegalArgumentException.class, () -> DumpedPrivateKey.fromBase58(Base58.encodeChecked(128, badCompression)));
        String testnet = Base58.encodeChecked(239, Utils.bigIntegerToBytes(BigInteger.TWO, 32));
        assertThrows(IllegalArgumentException.class, () -> DumpedPrivateKey.fromBase58(testnet));
        for(Network network : List.of(Network.TESTNET, Network.TESTNET4, Network.SIGNET, Network.REGTEST)) {
            Network.set(network);
            assertEquals(BigInteger.TWO, DumpedPrivateKey.fromBase58(testnet).getKey().getPrivKey());
            assertThrows(IllegalArgumentException.class, () -> DumpedPrivateKey.fromBase58(COMPRESSED_WIF));
        }
    }

    @Test
    void reusableAddressCannotExpandOrBecomeChangeBranch() {
        Wallet wallet = Wallet.fromSingleKey("Reusable", DumpedPrivateKey.fromBase58(COMPRESSED_WIF).getKey(), ScriptType.P2WPKH);
        WalletNode receive = wallet.getFreshNode(KeyPurpose.RECEIVE);
        receive.getTransactionOutputs().add(new BlockTransactionHashIndex(Sha256Hash.ZERO_HASH, 1, new Date(), 0L, 0, 10000));
        assertSame(receive, wallet.getFreshNode(KeyPurpose.RECEIVE, receive));
        assertSame(receive, wallet.getFreshNode(KeyPurpose.CHANGE, receive));
        wallet.getNode(KeyPurpose.RECEIVE).fillToIndex(1000);
        assertEquals(1, wallet.getNode(KeyPurpose.RECEIVE).getChildren().size());
        assertTrue(wallet.getNode(KeyPurpose.CHANGE).getChildren().isEmpty());
        assertEquals(1, wallet.getPurposeNodes().size());
        assertEquals(1, wallet.getWalletNodes().size());
        assertEquals(1, wallet.getWalletUtxos().size());
        Wallet copy = wallet.copy();
        assertEquals(receive.getAddress(), copy.getFreshNode(KeyPurpose.CHANGE).getAddress());
        assertEquals(1, copy.getWalletUtxos().size());
    }

    @Test
    void partialSpendsReturnTrackedChangeAndSignAllSupportedTypes() throws Exception {
        for(ScriptType scriptType : ADDRESSES.keySet()) {
            spendAndVerify(DumpedPrivateKey.fromBase58(COMPRESSED_WIF).getKey(), scriptType);
        }
        spendAndVerify(DumpedPrivateKey.fromBase58(UNCOMPRESSED_WIF).getKey(), ScriptType.P2PKH);
    }

    private void spendAndVerify(ECKey key, ScriptType scriptType) throws Exception {
        Wallet wallet = Wallet.fromSingleKey("Spend", key, scriptType);
        WalletNode addressNode = wallet.getFreshNode(KeyPurpose.RECEIVE);
        wallet.setStoredBlockHeight(800006);
        Transaction funding = new Transaction();
        funding.addInput(Sha256Hash.ZERO_HASH, 0, new Script(new byte[0]));
        funding.addOutput(1000000L, addressNode.getAddress());
        wallet.updateTransactions(Map.of(funding.getTxId(), new BlockTransaction(funding.getTxId(), 800000, new Date(), 0L, funding)));
        addressNode.getTransactionOutputs().add(new BlockTransactionHashIndex(funding.getTxId(), 800000, new Date(), 0L, 0, 1000000L));
        Address recipient = ScriptType.P2WPKH.getAddress(PolicyType.SINGLE_KEY, ECKey.fromPrivate(BigInteger.TWO));
        Payment payment = new Payment(recipient, "Payment", 100000L, false);
        // Excluding the reusable address must not cause an endless search for a derived change address.
        TransactionParameters params = new TransactionParameters(List.of(new MaxUtxoSelector()), Collections.emptyList(), List.of(payment), Collections.emptyList(),
                Set.of(addressNode), 5.0d, 1.0d, 1.0d, null, 800006, false, false, true);
        WalletTransaction transaction = assertTimeoutPreemptively(Duration.ofSeconds(5), () -> wallet.createWalletTransaction(params));
        assertEquals(2, transaction.getTransaction().getOutputs().size());
        TransactionOutput change = transaction.getTransaction().getOutputs().stream().filter(output -> output.getScript().equals(addressNode.getOutputScript())).findFirst().orElseThrow();
        assertTrue(change.getValue() > 890000L);
        assertTrue(wallet.isWalletOutputScript(change.getScript()));
        PSBT psbt = transaction.createPSBT();
        assertTrue(psbt.getExtendedPublicKeys().isEmpty());
        assertTrue(psbt.getPsbtInputs().getFirst().getDerivedPublicKeys().isEmpty());
        assertTrue(psbt.getPsbtInputs().getFirst().getTapDerivedPublicKeys().isEmpty());
        for(var output : psbt.getPsbtOutputs()) {
            assertTrue(output.getDerivedPublicKeys().isEmpty());
            assertTrue(output.getTapDerivedPublicKeys().isEmpty());
        }
        psbt.addKeyPathInformation(wallet);
        assertTrue(wallet.canSignAllInputs(psbt));
        assertEquals(wallet.getKeystores(), new ArrayList<>(wallet.getSigningKeystores(psbt)));
        wallet.sign(psbt);
        psbt.verifySignatures();
        assertTrue(psbt.isSigned());
        PSBT serialized = new PSBT(psbt.serialize());
        serialized.verifySignatures();
        wallet.finalise(serialized);
        assertTrue(serialized.isFinalized());
        Transaction signed = serialized.extractTransaction();
        assertEquals(2, signed.getOutputs().size());
        assertTrue(wallet.canSign(signed));
        assertTrue(wallet.getSignedKeystores(signed).get(signed.getInputs().getFirst()).containsValue(wallet.getKeystores().getFirst()));
    }

    @Test
    void encryptCopyUnlockAndClearPrivateMaterial() throws Exception {
        Wallet wallet = Wallet.fromSingleKey("Encrypted", DumpedPrivateKey.fromBase58(COMPRESSED_WIF).getKey(), ScriptType.P2TR);
        Wallet copy = wallet.copy();
        Address address = wallet.getFreshNode(KeyPurpose.RECEIVE).getAddress();
        SingleKey beforeEncryption = wallet.getKeystores().getFirst().getSingleKey();
        Key encryptionKey = new Argon2KeyDeriver().deriveKey("test-only password");
        wallet.encrypt(encryptionKey);
        assertTrue(wallet.isEncrypted());
        wallet.checkWallet();
        assertEquals(address, wallet.getFreshNode(KeyPurpose.RECEIVE).getAddress());
        assertArrayEquals(new byte[32], beforeEncryption.getSecretBytes());
        assertThrows(IllegalStateException.class, () -> wallet.getKeystores().getFirst().getSingleKey().getKey());
        Wallet encryptedCopy = wallet.copy();
        assertThrows(Exception.class, () -> encryptedCopy.decrypt("wrong password"));
        encryptedCopy.decrypt(encryptionKey);
        encryptedCopy.checkWallet();
        assertEquals(COMPRESSED_WIF, encryptedCopy.getKeystores().getFirst().getSingleKey().getKey().getPrivateKeyEncoded().toString());
        assertTrue(wallet.isEncrypted());
        wallet.decrypt("test-only password");
        wallet.checkWallet();
        encryptionKey.clear();
        encryptedCopy.clearPrivate();
        assertArrayEquals(new byte[32], encryptedCopy.getKeystores().getFirst().getSingleKey().getSecretBytes());
        assertEquals(COMPRESSED_WIF, copy.getKeystores().getFirst().getSingleKey().getKey().getPrivateKeyEncoded().toString());
    }
}
