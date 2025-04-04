export enum OTP_SUCCESS {
  GENERATE_OTP = 'OTP has been sent to your email.',
  VERIFIED_OTP = 'OTP has been verified successfully.',
}

export enum OTP_ERROR {
  GENERATE_OTP = 'An error occurred while generating otp.',
  NOT_VERIFIED_OTP = 'OTP verification failed.',
  VERIFIED_OTP = 'An error occurred while verifying otp.',
}
