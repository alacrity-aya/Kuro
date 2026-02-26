import { describe, it, expect } from 'vitest';
import {
  validateBandwidth,
  validateLatency,
  validateJitter,
  validatePacketLoss,
  validatePolicy,
  parseBandwidth,
  parseLatency,
  parsePacketLoss,
} from './policyValidator';

describe('policyValidator', () => {
  describe('validateBandwidth', () => {
    describe('valid values', () => {
      it('accepts "10Mbps"', () => {
        expect(validateBandwidth('10Mbps')).toBeNull();
      });

      it('accepts "1Gbps"', () => {
        expect(validateBandwidth('1Gbps')).toBeNull();
      });

      it('accepts "100Kbps"', () => {
        expect(validateBandwidth('100Kbps')).toBeNull();
      });

      it('accepts "500bps"', () => {
        expect(validateBandwidth('500bps')).toBeNull();
      });

      it('accepts decimal values like "1.5Mbps"', () => {
        expect(validateBandwidth('1.5Mbps')).toBeNull();
      });

      it('accepts values with spaces like "10 Mbps"', () => {
        expect(validateBandwidth('10 Mbps')).toBeNull();
      });

      it('accepts lowercase units like "10mbps"', () => {
        expect(validateBandwidth('10mbps')).toBeNull();
      });
    });

    describe('invalid values', () => {
      it('rejects "abc"', () => {
        expect(validateBandwidth('abc')).toBe('Invalid format. Use: 10Mbps, 1Gbps, 100Kbps, 500bps');
      });

      it('rejects "10"', () => {
        expect(validateBandwidth('10')).toBe('Invalid format. Use: 10Mbps, 1Gbps, 100Kbps, 500bps');
      });

      it('rejects "Mbps"', () => {
        expect(validateBandwidth('Mbps')).toBe('Invalid format. Use: 10Mbps, 1Gbps, 100Kbps, 500bps');
      });

      it('rejects empty string', () => {
        expect(validateBandwidth('')).toBe('Bandwidth is required');
      });

      it('rejects whitespace only', () => {
        expect(validateBandwidth('   ')).toBe('Bandwidth is required');
      });

      it('rejects "10 mb" (invalid unit)', () => {
        expect(validateBandwidth('10 mb')).toBe('Invalid format. Use: 10Mbps, 1Gbps, 100Kbps, 500bps');
      });
    });
  });

  describe('validateLatency', () => {
    describe('valid values', () => {
      it('accepts "10ms"', () => {
        expect(validateLatency('10ms')).toBeNull();
      });

      it('accepts "1s"', () => {
        expect(validateLatency('1s')).toBeNull();
      });

      it('accepts "500ms"', () => {
        expect(validateLatency('500ms')).toBeNull();
      });

      it('accepts decimal values like "0.5s"', () => {
        expect(validateLatency('0.5s')).toBeNull();
      });

      it('accepts values with spaces like "10 ms"', () => {
        expect(validateLatency('10 ms')).toBeNull();
      });
    });

    describe('invalid values', () => {
      it('rejects "abc"', () => {
        expect(validateLatency('abc')).toBe('Invalid format. Use: 10ms, 1s, 500ms');
      });

      it('rejects "10"', () => {
        expect(validateLatency('10')).toBe('Invalid format. Use: 10ms, 1s, 500ms');
      });

      it('rejects empty string', () => {
        expect(validateLatency('')).toBe('Latency is required');
      });

      it('rejects "10us" (microseconds not supported)', () => {
        expect(validateLatency('10us')).toBe('Invalid format. Use: 10ms, 1s, 500ms');
      });
    });
  });

  describe('validateJitter', () => {
    describe('valid values', () => {
      it('accepts "5ms"', () => {
        expect(validateJitter('5ms')).toBeNull();
      });

      it('accepts "0.5s"', () => {
        expect(validateJitter('0.5s')).toBeNull();
      });

      it('accepts "10ms"', () => {
        expect(validateJitter('10ms')).toBeNull();
      });
    });

    describe('invalid values', () => {
      it('rejects "abc"', () => {
        expect(validateJitter('abc')).toBe('Invalid format. Use: 5ms, 0.5s, 10ms');
      });

      it('rejects empty string', () => {
        expect(validateJitter('')).toBe('Jitter is required');
      });
    });
  });

  describe('validatePacketLoss', () => {
    describe('valid values', () => {
      it('accepts "0%"', () => {
        expect(validatePacketLoss('0%')).toBeNull();
      });

      it('accepts "0.1%"', () => {
        expect(validatePacketLoss('0.1%')).toBeNull();
      });

      it('accepts "1%"', () => {
        expect(validatePacketLoss('1%')).toBeNull();
      });

      it('accepts "50%"', () => {
        expect(validatePacketLoss('50%')).toBeNull();
      });

      it('accepts "100%"', () => {
        expect(validatePacketLoss('100%')).toBeNull();
      });

      it('accepts values with spaces like "1 %"', () => {
        expect(validatePacketLoss('1 %')).toBeNull();
      });
    });

    describe('invalid values', () => {
      it('rejects "abc"', () => {
        expect(validatePacketLoss('abc')).toBe('Invalid format. Use: 0.1%, 1%, 50%');
      });

      it('rejects "101%"', () => {
        expect(validatePacketLoss('101%')).toBe('Packet loss must be between 0% and 100%');
      });

      it('rejects "-1%"', () => {
        expect(validatePacketLoss('-1%')).toBe('Invalid format. Use: 0.1%, 1%, 50%');
      });

      it('rejects empty string', () => {
        expect(validatePacketLoss('')).toBe('Packet loss is required');
      });

      it('rejects "10" (missing %)', () => {
        expect(validatePacketLoss('10')).toBe('Invalid format. Use: 0.1%, 1%, 50%');
      });
    });
  });

  describe('validatePolicy', () => {
    it('returns isValid: true for valid policy', () => {
      const result = validatePolicy({
        bandwidth: '10Mbps',
        latency: '10ms',
        jitter: '5ms',
        packetLoss: '0.1%',
      });
      expect(result.isValid).toBe(true);
      expect(result.errors).toEqual({});
    });

    it('returns errors for all invalid fields', () => {
      const result = validatePolicy({
        bandwidth: 'abc',
        latency: 'xyz',
        jitter: 'invalid',
        packetLoss: '200%',
      });
      expect(result.isValid).toBe(false);
      expect(result.errors.bandwidth).toBeDefined();
      expect(result.errors.latency).toBeDefined();
      expect(result.errors.jitter).toBeDefined();
      expect(result.errors.packetLoss).toBeDefined();
    });

    it('returns partial errors for some invalid fields', () => {
      const result = validatePolicy({
        bandwidth: '10Mbps',
        latency: 'invalid',
        jitter: '5ms',
        packetLoss: '0.1%',
      });
      expect(result.isValid).toBe(false);
      expect(result.errors.bandwidth).toBeUndefined();
      expect(result.errors.latency).toBeDefined();
      expect(result.errors.jitter).toBeUndefined();
      expect(result.errors.packetLoss).toBeUndefined();
    });
  });

  describe('parseBandwidth', () => {
    it('parses "500bps" to 500', () => {
      expect(parseBandwidth('500bps')).toBe(500);
    });

    it('parses "100Kbps" to 100000', () => {
      expect(parseBandwidth('100Kbps')).toBe(100000);
    });

    it('parses "10Mbps" to 10000000', () => {
      expect(parseBandwidth('10Mbps')).toBe(10000000);
    });

    it('parses "1Gbps" to 1000000000', () => {
      expect(parseBandwidth('1Gbps')).toBe(1000000000);
    });

    it('returns null for invalid input', () => {
      expect(parseBandwidth('invalid')).toBeNull();
    });
  });

  describe('parseLatency', () => {
    it('parses "10ms" to 10', () => {
      expect(parseLatency('10ms')).toBe(10);
    });

    it('parses "1s" to 1000', () => {
      expect(parseLatency('1s')).toBe(1000);
    });

    it('parses "500ms" to 500', () => {
      expect(parseLatency('500ms')).toBe(500);
    });

    it('returns null for invalid input', () => {
      expect(parseLatency('invalid')).toBeNull();
    });
  });

  describe('parsePacketLoss', () => {
    it('parses "0.1%" to 0.1', () => {
      expect(parsePacketLoss('0.1%')).toBe(0.1);
    });

    it('parses "50%" to 50', () => {
      expect(parsePacketLoss('50%')).toBe(50);
    });

    it('returns null for invalid input', () => {
      expect(parsePacketLoss('invalid')).toBeNull();
    });
  });
});
