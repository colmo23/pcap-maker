function formatHexString(hexString) {
  // Remove all whitespace characters from the hex string
  const sanitizedHexString = hexString.replace(/\s/g, '');

  // Create an empty array to store the formatted hex string
  const formattedHexWithSpaces = [];

  // Iterate over the characters in the sanitized hex string
  for (let i = 0; i < sanitizedHexString.length; i += 2) {
    // Extract the current two characters
    const hexPair = sanitizedHexString.slice(i, i + 2);

    // Add the hex pair to the array with a space between them
    formattedHexWithSpaces.push(hexPair + ' ');

    // Add a carriage return after every 16 characters
    if ((i + 2) % 16 === 0) {
      formattedHexWithSpaces.push('\n');
    }
  }

  // Join the array of hex pairs with spaces and carriage returns into a single string
  return formattedHexWithSpaces.join('');
}

const hexString = 'abcdef1234567890  \n 9876543210';
const formattedHexString = formatHexString(hexString);
console.log(formattedHexString);


