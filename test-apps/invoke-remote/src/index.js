import { invokeRemote } from '@forge/api';

// Tier A: literal path inline in the second argument's object literal.
export async function inlineLiteral() {
  return invokeRemote('my-remote', {
    method: 'GET',
    path: '/rest/api/3/myself',
  });
}

// Tier A boundary: options is a variable built in the SAME function.
export async function localVar() {
  const options = { method: 'POST', path: '/local/path' };
  return invokeRemote('my-remote', options);
}

// Dynamic: path comes from a parameter (interprocedural) -> <dynamic> for Tier A.
export async function fromParam(options) {
  return invokeRemote('my-remote', options);
}
