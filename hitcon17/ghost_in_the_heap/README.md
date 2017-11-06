[Writeup by the creator](https://github.com/scwuaptx/CTF/tree/master/2017-writeup/hitcon/ghost_in_the_heap)


* **Feeing fastchunks bordering top will trigger `malloc_consolidate`**. I originally missed that, even though this bit me multiple times in the past.
    * Is this intentional? Wouldn't `malloc_trim` be responsible for such things?

* Because of this, my assumption was that the location of the fast chunk is final once allocated and worked from here. A somewhat interesting attempt was:
    * Leak libc (this anchors the fastchunk at the beginning of the heap)
    * **Attempt to create a pointer in libc we can use for unsafe unlinking. `last_remainder` seemed like a good candidate**
        * Allocate the three small chunks, free the first two, allocate one again
            * This creates a hole, then splits it and sets last_remainder to the where the second small chunk was
    * Free the third chunk
        * This will coalesce it with the second and move back top to the same spot as last_remainder
    * Now allocate again
        * It will be served from top
        * Create fd/bk in the chunk that use last_remainder to fake a valid list for unlink
        * Use the off-by-one to corrupt the LSB of top (unsetting PREV_INUSE)
        * Also take care of the new size checks in unlink
    * Now free the first chunk
        * This will unlink the second chunk in the consolidate forward phase, corrupting last_remainder in the process (which is non-consequential)
        * And create a chunk in the unsorted bin overlapping the still allocated second chunk completely.
    * This is the point where I didn't see a way forward and went on to 'quickly solve Baby FS'. And never returned.
