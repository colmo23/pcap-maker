document.addEventListener('DOMContentLoaded', () => {
    // const hexInput = document.getElementById('hex-input');
    const hexInput = document.querySelector('.hex-input');
    const lineNumbers = document.querySelector('.line-numbers');
    const asciiOutput = document.querySelector('.ascii-output');

    const BYTES_PER_LINE = 16;

    function updateEditor() {
        const cursorPosition = hexInput.selectionStart;
        const originalLength = hexInput.value.length;

        const rawText = hexInput.value.replace(/[^0-9a-fA-F]/g, '').toLowerCase();

        let formattedText = '';
        let asciiRepresentation = '';

        for (let i = 0; i < rawText.length; i += (BYTES_PER_LINE * 2)) {
            const lineHex = rawText.substring(i, i + (BYTES_PER_LINE * 2));
            
            const spacedLineHex = (lineHex.match(/.{1,2}/g) || []).join(' ');
            formattedText += spacedLineHex + '\n';

            let lineAscii = '';
            for (let j = 0; j < lineHex.length; j += 2) {
                const byte = lineHex.substr(j, 2);
                if (byte.length === 2) {
                    const decimalValue = parseInt(byte, 16);
                    if (decimalValue >= 32 && decimalValue <= 126) {
                        lineAscii += String.fromCharCode(decimalValue);
                    } else {
                        lineAscii += '.';
                    }
                } else {
                    lineAscii += ' ';
                }
            }
            asciiRepresentation += lineAscii + '\n';
        }
        
        hexInput.value = formattedText.slice(0, -1);

        const numberOfLines = (hexInput.value.match(/\n/g) || []).length + 1;
        lineNumbers.innerHTML = Array.from({ length: numberOfLines }, (_, i) =>
            `0x${(i * BYTES_PER_LINE).toString(16).padStart(8, '0')}`
        ).join('\n');
        
        asciiOutput.innerHTML = asciiRepresentation.slice(0, -1);
        
        const newLength = hexInput.value.length;
        const lengthDifference = newLength - originalLength;
        const newCursorPosition = cursorPosition + lengthDifference;
        
        hexInput.selectionStart = hexInput.selectionEnd = newCursorPosition > 0 ? newCursorPosition : cursorPosition;
    }

    hexInput.addEventListener('input', updateEditor);
    
    hexInput.addEventListener('scroll', () => {
        lineNumbers.scrollTop = hexInput.scrollTop;
        asciiOutput.scrollTop = hexInput.scrollTop;
    });

    if (hexInput.value) {
        updateEditor();
    }

    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            navigator.clipboard.writeText(btn.dataset.hex);
            const orig = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = orig; }, 1200);
        });
    });

    document.querySelectorAll('.use-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const field = document.getElementById(btn.dataset.field);
            if (field) {
                field.value = btn.dataset.hex;
                field.dispatchEvent(new Event('input'));
                field.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        });
    });
});
