import unittest
from inbound_inventory import inbound_inventory

class InboundRoutes(unittest.TestCase):
    def config(self,rules):
        return {'inbounds':[{'tag':t,'type':'vless'} for t in ('a','b')]+[{'tag':'internal','type':'socks'}], 'outbounds':[{'type':'direct','tag':'direct'}], 'route':{'rules':rules,'final':'direct'}}
    def test_shared_direct_keeps_every_configured_tag(self):
        a=inbound_inventory(self.config([]));self.assertEqual([x['tag'] for x in a],['a','b','internal']);self.assertTrue(all(x['routes']==['direct'] and not x['unknown'] for x in a))
    def test_protocol_and_authentication_are_distinct(self):
        c=self.config([])
        c['inbounds'][0]['users']=[{'name':str(n)} for n in range(14)]
        c['inbounds'] += [{'tag':'http-in','type':'http'},{'tag':'tun-in','type':'tun'},{'type':'socks'}]
        a=inbound_inventory(c)
        self.assertEqual(len(a[0]['auth_ids']),14)
        self.assertEqual(a[0]['auth_count'],14)
        self.assertNotIn('users',a[0])
        self.assertEqual([(x['tag'],x['type']) for x in a],[('a','vless'),('b','vless'),('internal','socks'),('http-in','http'),('tun-in','tun')])
    def test_rotation_and_missing_names(self):
        c=self.config([]);c['inbounds'][0]['users']=[{'name':'one','uuid':'SECRET1'},{'uuid':'SECRET2'}]
        a=inbound_inventory(c)[0];c['inbounds'][0]['users'][0]['uuid']='ROTATED'
        b=inbound_inventory(c)[0]
        self.assertEqual(a['auth_ids'],b['auth_ids']);self.assertEqual(a['auth_count'],2);self.assertEqual(a['auth_unsupported'],1)
        self.assertNotIn('SECRET',str(a));self.assertNotIn('one',str(a))
    def test_conditional_and_ruleset(self):
        a=inbound_inventory(self.config([{'inbound':['a'],'auth_user':['user'],'outbound':'proxy'},{'rule_set':['geo'],'outbound':'other'}]));self.assertEqual(a[0]['routes'],['direct','other','proxy']);self.assertEqual(a[1]['routes'],['direct','other'])
    def test_reject_before_route(self):
        a=inbound_inventory(self.config([{'inbound':['a'],'action':'reject'},{'inbound':['a'],'outbound':'proxy'}]));self.assertTrue(a[0]['unknown']);self.assertEqual(a[0]['routes'],[]);self.assertEqual(a[1]['routes'],['direct'])
    def test_exact_route_and_sniff(self):
        a=inbound_inventory(self.config([{'action':'sniff'},{'inbound':['a'],'outbound':'proxy'}]));self.assertEqual(a[0]['routes'],['proxy']);self.assertFalse(a[0]['unknown'])
    def test_logical_and_inverted_unknown(self):
        a=inbound_inventory(self.config([{'type':'logical','mode':'and','rules':[{'inbound':['a']},{'domain':['example.org']}],'outbound':'proxy'}]));self.assertEqual(a[0]['routes'],['direct','proxy']);self.assertEqual(a[1]['routes'],['direct','proxy'])

if __name__=='__main__':unittest.main()
