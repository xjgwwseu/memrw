DESCRIPTION = "memrw application"
SECTION = "memrw"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://memrw.c"

S = "${WORKDIR}"

do_compile() {
	${CC} ${LDFLAGS} memrw.c -o memrw
}

do_install() {
	install -d ${D}${bindir}
	install -m 0755 memrw ${D}${bindir}
}
