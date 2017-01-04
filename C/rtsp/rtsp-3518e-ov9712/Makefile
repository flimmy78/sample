INCLUDE=-I./include/
LIBS=./lib/libmpi.a ./lib/libVoiceEngine.a ./lib/libaec.a ./lib/libresampler.a ./lib/libanr.a ./lib/libisp.a ./lib/libsns_ov9712.a ./lib/lib_hiae.a ./lib/lib_hiawb.a ./lib/lib_hiaf.a -lpthread -lm
all:rtsp
rtsp:
	arm-hisiv100nptl-linux-gcc -o rtsp -Dhi3518 -DHICHIP=0x35180100 -DSENSOR_TYPE=OMNI_OV9712_DC_720P_30FPS -DHI_DEBUG -DHI_XXXX -DISP_V2 main.c ringfifo.c rtputils.c rtspservice.c rtsputils.c loadbmp.c sample_comm_audio.c sample_comm_isp.c sample_comm_sys.c sample_comm_vda.c sample_comm_venc.c sample_comm_vi.c sample_comm_vo.c sample_comm_vpss.c sample_venc.c $(INCLUDE) $(LIBS)
clean:
	rm -rfv rtsp