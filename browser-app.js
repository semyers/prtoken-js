window.addEventListener('load', () => {
    const tokenInput = document.getElementById('prt-token-input');
    const decryptButton = document.getElementById('decrypt-button');
    const resultsOutput = document.getElementById('results-output');

    // Sample PRT token for demonstration purposes.
    const SAMPLE_PRT_TOKEN = "AQAhA3E/ogZMjnn0NOr7xElireLgsf3flagn4bmcORkye4isACED26BvIEpa4rNsHRrLMNIyJ1OE9Wx8m45iZ+81wmRF5bfljwIhYnA2YQ==:";
    tokenInput.value = SAMPLE_PRT_TOKEN;

    function formatIPv6(buffer) {
        const parts = [];
        for (let i = 0; i < 16; i += 2) {
            parts.push(((buffer[i] << 8) | buffer[i + 1]).toString(16));
        }
        // Basic zero compression
        return parts.join(':').replace(/:(0:)+/, '::');
    }

    function printSignal(plaintextToken) {
        const signal = plaintextToken.signal;

        if (signal.every(byte => byte === 0)) {
            return `Signal is all zeros (raw): ${btoa(String.fromCharCode.apply(null, signal))}`;
        }

        const ipv4MappedPrefix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
        const prefixMatch = signal.slice(0, 12).every((val, i) => val === ipv4MappedPrefix[i]);

        if (signal.length === 16 && prefixMatch) {
            const ipv4Bytes = signal.slice(12);
            return `Signal (IP Address): ${Array.from(ipv4Bytes).join('.')}`;
        }

        if (signal.length === 16) {
            return `Signal (IP Address): ${formatIPv6(signal)}`;
        }

        return `Signal (raw): ${btoa(String.fromCharCode.apply(null, signal))}`;
    }

    decryptButton.addEventListener('click', async () => {
        const prtHeader = tokenInput.value.trim();
        if (!prtHeader) {
            resultsOutput.textContent = "Please paste a PRT token.";
            return;
        }

        resultsOutput.textContent = "Decrypting...";

        const result = await decryptTokenHeader(prtHeader);

        if (result) {
            const plaintextToken = await getPlaintextToken(result);
            if (plaintextToken) {
                const output = [
                    `Decrypted Token Bytes: ${btoa(String.fromCharCode.apply(null, result.plaintext))}`,
                    `Decrypted Token Length: ${result.plaintext.length} bytes`,
                    `Version: ${plaintextToken.version}`,
                    `t_ord: ${plaintextToken.ordinal}`,
                    printSignal(plaintextToken),
                    `HMAC Verification successful: ${plaintextToken.hmac_valid}`
                ].join('\n');
                resultsOutput.textContent = output;
            } else {
                resultsOutput.textContent = "Failed to get plaintext token.";
            }
        } else {
            resultsOutput.textContent = "Failed to decrypt token header.";
        }
    });
});