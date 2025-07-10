import { ExecutionContext, Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  protected shouldSkipThrottle(context: ExecutionContext): boolean {
    // NE engedjük át csak azért, mert @Public() van beállítva
    // Teljesen kiiktatjuk a skip-logikát → minden végpont throttled lesz
    return false;
  }
}
