"""Deterministic, non-authorizing HC01 feedback; never echo untrusted data."""
from __future__ import annotations
import json
import re
import secrets

VERSION='hc01-reason/v1'
TEMPLATES={
 'STAGE_SCOPE_VIOLATION':('The edit exceeds the active stage.','Continue within the authorized stage or request a host-approved transition.'),
 'PROTECTED_BY_ROOT':('The edit conflicts with the registered task boundary.','Choose a permitted task target or request operator review.'),
 'STATE_PRECONDITION_CHANGED':('A required resource version has changed.','Stop the dependent edit and request host revalidation.'),
 'CONTRACT_EXPIRED':('The task or stage contract is no longer active.','Request a new host-approved contract.'),
 'PHASE_INACTIVE':('The requested stage is inactive.','Use the trusted active stage or request operator review.'),
 'PARENT_REBIND_DENIED':('The request bypasses the active contract chain.','Keep the current stage root or request operator review.'),
 'SESSION_SCOPE_MISMATCH':('The contract belongs to a different session.','Request a new host-approved task registration.'),
 'UNSAFE_RESOURCE':('The resource identity cannot be safely authorized.','Use an explicit supported project resource or request operator review.'),
 'HC01_CALLBACK_UNAVAILABLE':('The contract check could not complete; coverage is unknown.','Stop protected edits and ask the operator to inspect Hook health.'),
 'CONTRACT_AUTHORITY_UNKNOWN':('Contract authority could not be verified.','Stop the protected edit and ask the operator to check registration.'),
}
ALIASES={'NOT_IN_PHASE_SCOPE':'STAGE_SCOPE_VIOLATION','STAGE_ROOT_ALREADY_BOUND':'PARENT_REBIND_DENIED',
         'DELEGATED_CONTRACT_INACTIVE':'PARENT_REBIND_DENIED','ROOT_NOT_EXECUTION_CONTRACT':'PARENT_REBIND_DENIED',
         'OUTSIDE_ROOT_SCOPE':'PROTECTED_BY_ROOT','INHERITED_DENY_VIOLATION':'PROTECTED_BY_ROOT',
         'UNSAFE_RESOURCE_IDENTITY':'UNSAFE_RESOURCE','UNSAFE_OR_UNPARSEABLE_PATCH':'UNSAFE_RESOURCE',
         'PROJECT_ROOT_IDENTITY_CHANGED':'UNSAFE_RESOURCE','PROJECT_ROOT_MISMATCH':'UNSAFE_RESOURCE'}


def render(code,*,mode='F1',reference=None):
    """Only host-owned enum codes and newly generated opaque references render."""
    if reference is None:reference='R-'+secrets.token_hex(12)
    if not isinstance(reference,str) or not re.fullmatch(r'R-[a-f0-9]{24}',reference):reference='R-'+secrets.token_hex(12)
    canonical=ALIASES.get(code,code) if isinstance(code,str) else 'CONTRACT_AUTHORITY_UNKNOWN'
    if canonical not in TEMPLATES:canonical='CONTRACT_AUTHORITY_UNKNOWN'
    if mode=='F0':visible_code='DENIED';text='[CLIM DENIED] Action denied.'
    else:
        visible_code=canonical;reason,guidance=TEMPLATES[canonical];text=f'[CLIM {canonical}] {reason} {guidance}'
    text+=' Ref: '+reference
    assert len(text)<=300
    reply={'hookSpecificOutput':{'hookEventName':'PreToolUse','permissionDecision':'deny','permissionDecisionReason':text}}
    return {'reply':reply,'decision_id':reference,'visible_code':visible_code,'reason_template_version':VERSION,
            'feedback_mode':mode if mode=='F0' else 'F1','text':text}


def safe_display_label(value):
    """Display only; never use this return value as an authorization path."""
    return value if isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,24}',value) else '[withheld]'
