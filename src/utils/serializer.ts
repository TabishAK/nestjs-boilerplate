import { HttpException } from '@nestjs/common';

export interface Serialized<T, K extends number = number> {
  data: T;
  status: K;
  message: string;
}

export function SerializeHttpResponse<T, K extends number = number>(
  data: T,
  status: K,
  message: string
): Serialized<T, K> {
  if (status >= 200 && status < 400) {
    return { data, status, message };
  }

  throw new HttpException({ status, data, message }, status);
}
