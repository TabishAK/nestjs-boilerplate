export enum AUTH_SUCCESS {
  ACCOUNT_CREATION = 'Your account has been successfully created. Please check your email address for the otp.',
  GOOGLE_ACCOUNT_CREATION = 'Your account has been successfully created.',
  ACCOUNT_LOGIN = 'Your account has been logged in successfully.',
  FORGOT_PASSWORD = 'The password reset email has been sent successfully.',
  RESET_PASSWORD = 'The password has been successfully reset.',
  VALID_TOKEN = 'Successfully validate the token.',
}

export enum AUTH_ERRORS {
  INCORRECT_CREDENTIALS = 'Incorrect email or password.',
  USER_NOT_FOUND = 'Unable to find the user.',
  DUPLICATE_EMAIL = 'User with same email already exist.',
  ACCOUNT_CREATION = 'An error occurred while creating new user.',
  ACCOUNT_LOGIN = 'An error occurred while logging the account.',
  UNAUTHORIZED = 'You are not authorized to access this operation.',
  FORGOT_PASSWORD = 'An error occurred while resetting user password.',
  INVALID_TOKEN = 'Your token is not validate.',
  EMAIL_NOT_VERIFIED = 'Your email is not verified.',
}
