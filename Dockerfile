FROM ubuntu:20.04
MAINTAINER R.J. McDown

ENV DEBIAN_FRONTEND "noninteractive"

#
# Install Updates
#
RUN apt update -y \
	&& apt upgrade -y \
	&& apt install sudo -y \
	&& apt install dos2unix -y \
	&& apt install git -y \
	&& apt install tmux -y \
	&& apt install net-tools -y \
	&& apt install nano -y \
	&& apt install python3 -y \
	&& apt install python3-pip -y

# RUN git clone https://github.com/SecureAuthCorp/impacket.git \
RUN git clone https://github.com/BeetleChunks/impacket.git \
	&& cd ./impacket \
	&& pip3 install .

# Clone Responder
RUN git clone https://github.com/lgandx/Responder.git /Responder

#
# Create new user, add to sudoers, and sudo no-password
#
RUN useradd -ms /bin/bash dlogmas \
	&& echo "dlogmas:dlogmas" | chpasswd && adduser dlogmas sudo \
	&& echo 'dlogmas ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

#
# Add application code and configs
#
RUN mkdir /home/dlogmas/ssploit
RUN mkdir /home/dlogmas/smbserver

ADD ./ssploit/ /home/dlogmas/ssploit/
ADD ./smbserver/ /home/dlogmas/smbserver/

RUN chmod -R 755 /home/dlogmas/ssploit \
	&& mkdir /home/dlogmas/ssploit/logs \
	&& chmod +x /home/dlogmas/ssploit/spool_sploit.py

RUN chmod -R 755 /home/dlogmas/smbserver \
	&& mkdir /home/dlogmas/smbserver/logs \
	&& mkdir /home/dlogmas/smbserver/share \
	&& chmod +x /home/dlogmas/smbserver/smb_server.py

RUN mv /home/dlogmas/ssploit/banner.sh /home/dlogmas/.banner.sh \
	&& chmod 544 /home/dlogmas/.banner.sh

RUN mv /home/dlogmas/ssploit/bashrc.conf /home/dlogmas/.bashrc \
	&& chmod 644 /home/dlogmas/.bashrc

RUN dos2unix /home/dlogmas/ssploit/spool_sploit.py
RUN dos2unix /home/dlogmas/smbserver/smb_server.py

#
# Give application access to new user
#
RUN chown -R dlogmas:dlogmas /home/dlogmas/ssploit \
	&& chown -R dlogmas:dlogmas /home/dlogmas/smbserver \
	&& chown dlogmas:dlogmas /home/dlogmas/.bashrc

#
# Set interactive user to new user
#
USER dlogmas
WORKDIR /home/dlogmas/ssploit
CMD /bin/bash