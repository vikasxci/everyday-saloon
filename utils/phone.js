// Canonical form for Indian mobiles is the bare 10 digits:
// "+91 98765-43210", "919876543210" and "09876543210" all become "9876543210".
function normPhone(v) {
  const raw = String(v ?? '').trim();
  if (!raw) return '';
  const digits = raw.replace(/\D/g, '');
  if (digits.length === 12 && digits.startsWith('91')) return digits.slice(2);
  if (digits.length === 11 && digits.startsWith('0'))  return digits.slice(1);
  return digits;
}

const isPhone = p => /^\d{10,15}$/.test(p);

// Older records were stored exactly as typed, so lookups try every common spelling.
function phoneVariants(v) {
  const raw = String(v ?? '').trim();
  const n = normPhone(raw);
  return [...new Set([raw, n, n && `+91${n}`, n && `91${n}`, n && `0${n}`, n && `+91 ${n}`].filter(Boolean))];
}

module.exports = { normPhone, isPhone, phoneVariants };
