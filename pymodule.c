#include <Python.h>
#include "common.h"
#include "binary.h"
#include <setjmp.h>
#include <pthread.h>

jmp_buf jmp;

static void dumb_death(const char *message) {

}

static void dumb_setjmp() {
    setjmp(jmp);
    set_death_func(dumb_death);
}

typedef struct {
    PyObject_HEAD
    struct binary binary;
    PyObject *source;
} Binary;

static PyObject *Binary_new(PyTypeObject *type, PyObject *args, PyObject *kwargs) {
    Binary *self = type->tp_alloc(type, 0);
    if(self != NULL) {
        b_init(&self->binary);
        self->source = NULL;
    }
    return (PyObject *) self;
}

static int Binary_init(Binary *self, PyObject *args, PyObject *kwargs) {
    PyObject *macho, *dyldcache;

    static char *kwlist[] = {"macho", "dyldcache", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwargs, "|OO", kwlist, &macho, *dyldcache)) return -1;
    
    if((macho && dyldcache) || (!macho && !dyldcache)) {
        PyErr_SetString(PyExc_TypeError, "expected macho *or* dyldcache");
        return NULL;
    }
    
    PyObject *data = macho ? macho : dyldcache;

    PyBufferProcs *buffer = data->tp_as_buffer;
    Py_ssize_t size;
    if(!buffer || !buffer->bf_getreadbuffer || !buffer->bf_getsegcount || buffer->bf_getsegcount(data, &size) != 1) {
        PyErr_SetString(PyExc_TypeError, "expected buffer");
        return NULL;
    }
    if(size < 0) {
        PyErr_SetString(PyExc_TypeError, "buffer has negative size");
        return NULL;
    }

    void *ptr;
    Py_ssize_t size2 = buffer->bf_get_readbuffer(data, 0, &ptr);
    if(size2 < 0) {
        PyErr_SetString(PyExc_TypeError, "buffer has negative size");
        return NULL;
    }

    if(mysetjmp()) return NULL;

    prange_t pr = {ptr, (size_t) size2};

    if(macho) {
        b_prange_load_macho(&self->binary, pr);
    } else {
        b_prange_load_dyldcache(&self->binary, pr);
    }
    
    Py_INCREF(self->source = data);
}

static PyMethodDef Binary_methods[] = {
    {"read8", (PyCFunction) Binary_read8, METH_VARARGS,
     "Read 8-bit value"},
    {"read16", (PyCFunction) Binary_read16, METH_VARARGS,
     "Read 16-bit value"},
    {"read32", (PyCFunction) Binary_read32, METH_VARARGS,
     "Read 32-bit value"},
    {"read64", (PyCFunction) Binary_read64, METH_VARARGS,
     "Read 64-bit value"},
};

static PyTypeObject BinaryType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "data.binary",             /*tp_name*/
    sizeof(noddy_NoddyObject), /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    0,                         /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,        /*tp_flags*/
    "binary",                  /* tp_doc */
    0,		                   /* tp_traverse */
    0,		                   /* tp_clear */
    0,		                   /* tp_richcompare */
    0,		                   /* tp_weaklistoffset */
    0,		                   /* tp_iter */
    0,		                   /* tp_iternext */
    Binary_methods,            /* tp_methods */
    Binary_members,            /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)Binary_init,     /* tp_init */
    0,                         /* tp_alloc */
    Binary_new,                /* tp_new */
};

static PyMethodDef DataMethods[] = {
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initdata(void) {
    if(PyType_Ready(&data_BinaryType) < 0) return;
    
    PyObject *m = Py_InitModule("data", DataMethods);
    if(!m) return;

    Py_INCREF(_data_BinaryType);
    PyModule_AddObject(m, "binary", (PyObject *) &data_BinaryType);

}
