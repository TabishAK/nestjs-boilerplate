import * as bcrypt from 'bcrypt';

export const createHashPassword = async (password: string) => {
  const saltOrRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltOrRounds);
  return hashedPassword;
};

export const generateRandomString = (length = 10) =>
  Array.from(
    { length },
    () =>
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+[]{}|;:,.<>?'[
        Math.floor(Math.random() * 84)
      ]
  ).join('');

export const generateRandomOTPNumber = (length: number) => {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error('Length must be a positive integer');
  }

  let otp = '';
  for (let i = 0; i < length; i++) {
    otp += Math.floor(Math.random() * 10); // Generates a random digit (0-9)
  }

  return otp;
};
