def register_success(rq):

    return f"REGISTERED {rq}"

def register_denied(rq, reason):

    return f"REGISTER-DENIED {rq} {reason}"

def subscribed(rq):

    return f"SUBSCRIBED {rq}"

def subscription_denied(rq, reason):

    return f"SUBSCRIPTION-DENIED {rq} {reason}"