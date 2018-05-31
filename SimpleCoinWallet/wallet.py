from .SimpleCoinV4 import User as UserWallet, SimpleBlockChain, PleaseMine, RequestTransection
from .models import UserInfo, rtxn, User as UserAdmin, stxn
import pickle
import json


sbc = SimpleBlockChain()

def getchain():
    return json.dumps(sbc.chain, sort_keys=True, indent=4, separators=(',', ': '))

def conform_txn(txn):
    return sbc.conform_txn(txn)

def UserInfoBalance(user):
    a = UserInfo.objects.filter(acc = user)
    if a:
        a = a[0]
        return sbc.get_address_balance(a.accid)
    else:
        pass
    return False

# new user 
def new_user(user, username):
    u = UserWallet()
    print u.publickey
    account_id   = user
    account_addr = u.address
    account_auth = pickle.dumps(u)
    account_bal  = 0

    db = UserInfo()
    db.acc     = account_id
    db.accid   = account_addr
    db.authobj = account_auth
    db.balance = account_bal
    db.save()

    return True

def create_transection(user, receiver, coin):
    # Quit if Amount is Zero
    if float(coin) < 0:
        return False

    suser = UserInfo.objects.filter(acc=user)[0]
    ruser = UserInfo.objects.filter(accid=receiver)[0]
    sender =  suser.accid
    receiver = receiver
    amount = sbc.get_address_balance(sender)
    ccoin = float(float(amount) - (float(coin) + 0.1))
    coin = float(coin)
    rt = rtxn.objects.filter(acc= suser.acc)

    r = u''
    
    for i in rt:
        r = r + i.transections.__str__()
    print r
    trans = RequestTransection(pickle.loads(suser.authobj))
    trans.create_transection(
        category='send', 
        sender=sender, 
        receiver=receiver, 
        fee='0.1' ,
        coin=str(coin),
        ccoin = str(ccoin),
        txni= r 
    )
    if ccoin < 0:
        return False

    txn = trans.transection['txn']

    if mine(trans):
        # Save In Sent Page [Sender]
        for i in rt:
            if conform_txn(i.transections):
                s = stxn()
                s.acc = suser.acc
                s.transections = i.transections
                s.save()
            # Save In Sent Page [Sender]

        # Receiver Receive Account
        if conform_txn(txn):    
            s = rtxn()
            s.acc = ruser.acc
            s.transections = txn
            s.save()
        
            # Delete From Receive [Sender]

            for i in rt:
                i.delete()
        
            if float(ccoin):
                # Insert current transection as change in receive page [Sender]
                r = rtxn()
                r.acc = suser.acc
                r.transections = txn
                r.save()
        sbc.refresh()
        
        
        return True

    return False

def startblockchain(request):
    a = UserInfo.objects.all()
    print "Starting Chain By ",a
    if a and sbc.check_chain_len()<3:
        a = a[0]     
        print "Mining Process by : ", a.accid
        miner = PleaseMine(sbc, pickle.loads(a.authobj))
        r = rtxn()
        r.acc = a.acc
        r.transections = miner.reward_txn['txn']
        r.save()
        sbc.refresh()
        return True
        
    elif len(a)==0:
        user = UserAdmin.objects.all()[0]
        print "Generating Admin Authentication Object."
        new_user(user, user.username)
        startblockchain(request)
        sbc.refresh()
        return True
    else:
        pass
    return False              

def mine(txn=None):
    if txn:
        a = UserInfo.objects.all()[0]
        miner = PleaseMine(sbc, pickle.loads(a.authobj), transreq=[txn])
        # miner reward verification
        if miner.done:

            r = rtxn()
            r.acc = a.acc
            r.transections = miner.reward_txn['txn']
            r.save()
            sbc.refresh()
            return True
        else:
            return False

    return False