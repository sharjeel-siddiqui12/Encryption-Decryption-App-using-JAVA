package is;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

public class RSADSAEncryptionAppSwing1 extends JFrame {

    private JTextField plainTextField;
    private JTextField keyTextField;
    private JTextArea resultTextArea;
    private JTextArea decryptedTextArea;

    private byte[] encryptedText;
    
    private byte[] decryptedText;
    private KeyPair keyPair;
    
    
    private byte[] signature;

    
    public RSADSAEncryptionAppSwing1() {
        setTitle("RSA-DSA Encryption App");
        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setResizable(true);

        // Create components
        plainTextField = new JTextField();
        keyTextField = new JTextField();
        JButton encryptButton = new JButton("Encrypt");
        JButton decryptButton = new JButton("Decrypt");

        resultTextArea = new JTextArea();
        decryptedTextArea = new JTextArea();

        // Set layout
        setLayout(new GridLayout(1, 2));

        // Panel for the left side (image)
        JPanel imagePanel = new JPanel(new BorderLayout());
        imagePanel.setBorder(BorderFactory.createEmptyBorder(130, 10, 10, 10));
        imagePanel.setBackground(new Color(251,255,239)); // Skin color background

        // Set image icon in the top-left corner
        ImageIcon imageIcon = new ImageIcon("cipher.png"); // Replace with the actual path
        JLabel imageLabel = new JLabel(imageIcon);
        imagePanel.add(imageLabel, BorderLayout.NORTH);

        // Panel for the right side (text fields and result)
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        rightPanel.setBackground(new Color(251,255,239)); // Skin color background

        // Panel for text fields and buttons
        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new GridLayout(3, 2, 10, 10));
        inputPanel.setBackground(new Color(251,255,239)); // Skin color background

        inputPanel.add(new JLabel("Enter Plain Text:"));
        inputPanel.add(plainTextField);
        inputPanel.add(new JLabel("Enter Key:"));
        inputPanel.add(keyTextField);
        inputPanel.add(encryptButton);
        inputPanel.add(decryptButton);

        // Panel for result area
        JPanel resultPanel = new JPanel(new BorderLayout());
        resultPanel.add(new JLabel("Result:"), BorderLayout.NORTH);
        resultPanel.setBackground(new Color(251,255,239)); // Skin color background

        // Enable line wrap for resultTextArea
        resultTextArea.setLineWrap(true);
        resultTextArea.setWrapStyleWord(true);

        resultPanel.add(new JScrollPane(resultTextArea), BorderLayout.CENTER);

        // Panel for decrypted text area
        JPanel decryptedPanel = new JPanel(new BorderLayout());
        decryptedPanel.add(new JLabel("Decrypted Text:"), BorderLayout.NORTH);
        decryptedPanel.setBackground(new Color(251,255,239)); // Skin color background

        // Enable line wrap for decryptedTextArea
        decryptedTextArea.setLineWrap(true);
        decryptedTextArea.setWrapStyleWord(true);

        decryptedPanel.add(new JScrollPane(decryptedTextArea), BorderLayout.CENTER);

        // Add components to rightPanel
        rightPanel.add(inputPanel, BorderLayout.NORTH);
        rightPanel.add(resultPanel, BorderLayout.CENTER);
        rightPanel.add(decryptedPanel, BorderLayout.SOUTH);

        // Set background colors
        encryptButton.setBackground(new Color(50, 120, 220)); // Blue
        decryptButton.setBackground(new Color(50, 120, 220)); // Blue

        // Set button text color
        encryptButton.setForeground(Color.WHITE);
        decryptButton.setForeground(Color.WHITE);

        // Add left and right panels to the main frame
        add(imagePanel);
        add(rightPanel);

        // Set up event handler for the Encrypt button
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    performEncryption();
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });

        // Set up event handler for the Decrypt button
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    performDecryption();
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });
    }
    
    private KeyPair generateDSAKeyPair() throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
    SecureRandom secureRandom = new SecureRandom();
    keyPairGenerator.initialize(2048, secureRandom);
    return keyPairGenerator.generateKeyPair();
}


    private KeyPair generateRSAKeyPair(String seed) throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
    SecureRandom secureRandom = new SecureRandom(seed.getBytes());
    keyPairGenerator.initialize(2048, secureRandom);
    return keyPairGenerator.generateKeyPair();
}

    private byte[] encryptRSA(byte[] originalContent, PublicKey publicKey) throws Exception {


        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKeyBytes = rsaCipher.doFinal(originalContent);

      

   
return encryptedKeyBytes;
    }
    
    
    private byte[] decryptRSA(byte[] encryptedText, PrivateKey privateKey) throws Exception {

        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = rsaCipher.doFinal(encryptedText);
        return decryptedKeyBytes;
    }
    
    private boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
    Signature dsa = Signature.getInstance("SHA256withRSA", "SunRsaSign");
    dsa.initVerify(publicKey);
    dsa.update(data);
    return dsa.verify(signature);
}
    

private void performDecryption() throws Exception {
    if (keyPair == null) {
        JOptionPane.showMessageDialog(this, "Please perform encryption first to generate the key pair.", "Error", JOptionPane.ERROR_MESSAGE);
        return;
    }

    if (encryptedText == null || signature == null) {
        JOptionPane.showMessageDialog(this, "No encrypted text or signature available for decryption.", "Error", JOptionPane.ERROR_MESSAGE);
        return;
    }

    // Verify the digital signature
    if (verifySignature(encryptedText, signature, keyPair.getPublic())) {
        decryptedText = decryptRSA(encryptedText, keyPair.getPrivate());
        decryptedTextArea.setText("Decrypted Text: " + new String(decryptedText));
        JOptionPane.showMessageDialog(this, "Digital signature verification success.", "verified", JOptionPane.DEFAULT_OPTION);
    } else {
        JOptionPane.showMessageDialog(this, "Digital signature verification failed.", "Error", JOptionPane.ERROR_MESSAGE);
    }
}

    private byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
    Signature dsa = Signature.getInstance("SHA256withRSA", "SunRsaSign");
    dsa.initSign(privateKey);
    dsa.update(data);
    return dsa.sign();
}


    private void performEncryption() throws Exception {
        String plainText = plainTextField.getText();
        String key = keyTextField.getText();
        

        if (plainText.equals("") && key.equals("")) {
            JOptionPane.showMessageDialog(this, "Please fill the fields first.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        } else if (plainText.equals("")) {
            JOptionPane.showMessageDialog(this, "Please fill the plain text first.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        } else if (key.equals("")) {
            JOptionPane.showMessageDialog(this, "Please fill the key first.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        } else {
            // Apply arithmetic operation on the key and calculate the sum of digits
            int sumOfDigits = calculateSumOfDigits(key);

            // Apply hashing on the sum of digits
            String modifiedKey = hashToAESLength(Integer.toString(sumOfDigits));

            keyPair = generateRSAKeyPair(modifiedKey);  // Store the key pair

            encryptedText = encryptRSA(plainText.getBytes(), keyPair.getPublic());
           
            signature = signData(encryptedText, keyPair.getPrivate());

    resultTextArea.setText("Original Text: " + plainText + "\n" +
            "Encrypted Text: " + new String(encryptedText) + "\n" +
            "Signature: " + bytesToHex(signature) + "\n" +
            "Sum of Digits: " + sumOfDigits + "\n" +
            "Hashed Key: " + bytesToHex(modifiedKey.getBytes())
    );
        }
    }

    private int calculateSumOfDigits(String key) {
        int sum = 0;
        for (char digit : key.toCharArray()) {
            if (Character.isDigit(digit)) {
                sum += Character.getNumericValue(digit);
            }
        }
        return sum;
    }

    private String hashToAESLength(String originalKey) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = sha256.digest(originalKey.getBytes());
        byte[] truncatedHash = new byte[32];
        System.arraycopy(hashBytes, 0, truncatedHash, 0, Math.min(hashBytes.length, truncatedHash.length));
        return Base64.getEncoder().encodeToString(truncatedHash);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String args[]) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new RSADSAEncryptionAppSwing1().setVisible(true);
            }
        });
    }
}
