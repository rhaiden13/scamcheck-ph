#!/usr/bin/env node
const failures=[];
const req=(k)=>{if(!process.env[k])failures.push(`${k} is missing`)};
req('ADMIN_EMAIL');req('ADMIN_PASSWORD');
if(process.env.NODE_ENV==='production'){
  req('DATABASE_URL');req('APP_BASE_URL');req('SESSION_SECRET');
  if((process.env.SESSION_SECRET||'').length<32)failures.push('SESSION_SECRET must be at least 32 characters in production');
  if(['ChangeMe123!','replace-with-a-strong-password','replace-with-a-unique-strong-password'].includes(process.env.ADMIN_PASSWORD))failures.push('ADMIN_PASSWORD is still a default value');
  req('PAYMONGO_SECRET_KEY');req('PAYMONGO_WEBHOOK_SECRET');
  if(!/^sk_(test|live)_/.test(process.env.PAYMONGO_SECRET_KEY||''))failures.push('PAYMONGO_SECRET_KEY must start with sk_test_ or sk_live_');
  if(!/^whsk_/.test(process.env.PAYMONGO_WEBHOOK_SECRET||''))failures.push('PAYMONGO_WEBHOOK_SECRET must start with whsk_');
  if((process.env.EMAIL_PROVIDER||'').toLowerCase()!=='resend')failures.push('EMAIL_PROVIDER must be resend in production');
  req('RESEND_API_KEY');req('RESEND_FROM');
  if((process.env.STORAGE_PROVIDER||'').toLowerCase()!=='s3')failures.push('STORAGE_PROVIDER must be s3 in production');
  req('S3_BUCKET');req('S3_REGION');req('AWS_ACCESS_KEY_ID');req('AWS_SECRET_ACCESS_KEY');
}
if(failures.length){console.error('Production configuration check failed:');for(const x of failures)console.error(' - '+x);process.exit(1)}
console.log('Production configuration check passed.');
