import * as bcrypt from 'bcrypt';

export const getCurrentFullYear = () => new Date().getFullYear();

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
