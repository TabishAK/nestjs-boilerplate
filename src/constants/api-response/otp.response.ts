export enum OTP_SUCCESS {
  GENERATE_OTP = 'OTP has been sent to your email.',
  VERIFIED_OTP = 'OTP has been verified successfully.',
}

export enum OTP_ERROR {
  OTP_NOT_VERIFIED = 'OTP verification failed.',
  OTP_EXPIRED = 'This OTP has expired.',
}
