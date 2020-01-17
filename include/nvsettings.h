#ifndef NVSETTINGS_H
#define NVSETTINGS_H

typedef struct
{
    unsigned int long tid;
    struct {
        int value;
    } GPUCurrentFanSpeedRPM;
    struct {
        int value;
    } GPUCurrentFanSpeed;
    struct {
        int value;
    } GPUFanControlType;
    struct {
        int value;
    } GPUMemoryInterface;
    struct {
        int value;
    } Irq;
    struct {
        int value;
    } BusType;
    struct {
        int value;
    } CUDACores;
} nvfunc;

#endif

