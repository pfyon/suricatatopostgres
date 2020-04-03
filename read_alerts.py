#!/usr/bin/env python3

import argparse
import datetime
import gzip
import json
import logging
import os
import psycopg2
import signal
import socket
import sys
import threading

def processMessage(msg, cursor):
	try:
		#Every event should have these fields
		ts 		= datetime.datetime.strptime(msg['timestamp'], "%Y-%m-%dT%H:%M:%S.%f%z")
		src_ip 		= msg['src_ip']
		src_port 	= msg.get('src_port', None)
		dest_ip 	= msg['dest_ip']
		dest_port 	= msg.get('dest_port', None)
		proto		= msg['proto']
		flow_id 	= msg['flow_id']

		cursor.execute("""INSERT INTO events (ts, src_ip, src_port, dest_ip, dest_port, proto, flow_id) VALUES (%s, %s, %s, %s, %s, %s, %s)""", (ts, src_ip, src_port, dest_ip, dest_port, proto, flow_id))

		if 'dns' in msg:
			dns_type = msg['dns']['type']
			rrtype = msg['dns'].get('rrtype', None)
			rrname = msg['dns'].get('rrname', None)
			rdata = msg['dns'].get('rdata', None)

			cursor.execute("""INSERT INTO dns (ts, type, rrtype, rrname, rdata, flow_id) VALUES (%s, %s, %s, %s, %s, %s)""", (ts, dns_type, rrtype, rrname, rdata, flow_id))

		if 'flow' in msg:
			pkts_toserver = msg['flow']['pkts_toserver']
			pkts_toclient = msg['flow']['pkts_toclient']
			bytes_toserver = msg['flow']['bytes_toserver']
			bytes_toclient = msg['flow']['bytes_toclient']
			flow_start = msg['flow']['start']
			flow_end = msg['flow'].get('end', None)
			state = msg['flow'].get('state', None)
			reason = msg['flow'].get('reason', None)

			cursor.execute("""INSERT INTO flow (ts, pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient, flow_start, flow_end, state, reason, flow_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""", (ts, pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient, flow_start, flow_end, state, reason, flow_id))

		if 'http' in msg:
			method = msg['http'].get('http_method', None)
			hostname = msg['http'].get('hostname', None)
			url = msg['http'].get('url', None)
			referrer = msg['http'].get('http_refer', None)
			user_agent = msg['http'].get('http_user_agent', None)
			content_type = msg['http'].get('http_content_type', None)
			status = msg['http'].get('status', None)
			length = msg['http'].get('length', None)

			cursor.execute("""INSERT INTO http (ts, method, hostname, url, referrer, user_agent, content_type, status, length, flow_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""", (ts, method, hostname, url, referrer, user_agent, content_type, status, length, flow_id))
		if 'tls' in msg:
			issuerdn = msg['tls'].get('issuerdn', None)
			subject = msg['tls'].get('subject', None)
			sni = msg['tls'].get('sni', None)
			serial = msg['tls'].get('serial', None)
			notbefore = msg['tls'].get('notbefore', None)
			notafter = msg['tls'].get('notafter', None)
			fingerprint = msg['tls'].get('fingerprint', None)
			version = msg['tls'].get('version', None)
			session_resumed = msg['tls'].get('session_resumed', None)

			if notbefore is not None:
				notbefore = datetime.datetime.strptime(notbefore, "%Y-%m-%dT%H:%M:%S")
			if notafter is not None:
				notafter = datetime.datetime.strptime(notafter, "%Y-%m-%dT%H:%M:%S")

			cursor.execute("""INSERT INTO tls (ts, issuerdn, subject, sni, serial, notbefore, notafter, fingerprint, version, session_resumed, flow_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""", (ts, issuerdn, subject, sni, serial, notbefore, notafter, fingerprint, version, session_resumed, flow_id))

		if 'alert' in msg:
			description = msg['alert']['signature']
			action = msg['alert']['action']
			category = msg['alert']['category']
			rev = msg['alert']['rev']
			gid = msg['alert']['gid']
			sid = msg['alert']['signature_id']
			severity = msg['alert']['severity']

			cursor.execute("""INSERT INTO alert (ts, description, action, category, rev, gid, sid, severity, flow_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""", (ts, description, action, category, rev, gid, sid, severity, flow_id))

		#TODO: this is debug
		for key in msg:
			if isinstance(msg[key], dict) and key not in ('flow', 'tls', 'http', 'dns', 'alert', 'tcp', 'fileinfo', 'vars', 'drop', 'metadata'):
				print("{k}: {v}".format(k=key, v=msg[key]))
	except Exception as e:
		logging.exception(e)
		logging.error(msg)

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("path", help="Path to eve.json file or unix_dgram socket", default="/var/log/suricata/eve-unix.sock")
	parser.add_argument("--debug", action='store_true', dest='debug', default=False)
	args = parser.parse_args()

	logging.basicConfig(stream=sys.stdout, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

	log = logging.getLogger("read_alerts.py")
	if args.debug:
		log.setLevel(logging.DEBUG)
	else:
		log.setLevel(logging.INFO)

	die_flag = threading.Event()

	signal.signal(signal.SIGTERM, lambda signal, frame: die_flag.set())
	signal.signal(signal.SIGINT, lambda signal, frame: die_flag.set())

	use_socket = True

	if os.path.exists(args.path):
		if not os.path.isfile(args.path):
			#Existing unix socket, delete it
			try:
				log.info("Deleting existing unix socket '{path}'".format(path=args.path))
				os.unlink(args.path)
			except OSError as e:
				if os.path.exists(args.path):
					raise(e)
		else:
			use_socket = False

			try:
				f = gzip.GzipFile(args.path, mode='r')
				f.peek(10) #Test to see if it's a real gzip file
				log.debug("'{path}' is a gzip file".format(path=args.path))
			except OSError as e:
				#Not gzipped
				f = open(args.path, 'r')
				log.debug("'{path}' is a regular file".format(path=args.path))

	log.info("Connecting to database")
	con = psycopg2.connect(database="suricata", user="suricata")
	con.autocommit = False
	cursor = con.cursor()

	if use_socket:
		#Create a new socket and connect to it
		log.info("Creating unix socket '{path}'".format(path=args.path))
		sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
		sock.bind(args.path)
		sock.settimeout(1.0)

		log.debug("Starting listening on socket")
		while not die_flag.is_set():
			try:
				msg = json.loads(sock.recv(4096).decode("utf-8"))
				processMessage(msg, cursor)
				con.commit()
			except socket.timeout:
				pass
	else:
		log.info("Starting to process '{path}'".format(path=args.path))
		for line in f:
			if die_flag.is_set():
				break
			msg = json.loads(line)
			processMessage(msg, cursor)
		con.commit()
