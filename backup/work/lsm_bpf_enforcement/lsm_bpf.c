



int whitelist_bprm_check_security(struct linux_binprm *bprm)
{
  struct task_struct *task=current;	//get_curent
  kuid_t uid=task->cred->uid;

  //The target we are checking
  struct dentry *dentry=bprm->file->f_path.dentry;
  struct inode *inode=d_backing_inode(dentry);

  //size of the attribute,if any.
  int size=0;
  char att[100];
  //Root can access everything.
  if(uid.val==0)
  {
     return 0;
  }

  //If there is not an attribute,allow the access.
  //Otherwise, if not verify deny it.
  size=__vfs_getxattr(dentry,inode,key,att,100);
  if(size>0)
  {
      if(strcmp(att, "verified")==0)	//verified
      {
      	printk(KERN_INFO "[Execsec] call [whitelist_check] of %s with %s allowing access for UID %d\n",bprm->filename,att, uid.val);
      	return 0;
      }
      else
      {
      	printk(KERN_INFO "[Execsec] call [whitelist_check] of %s with %s deny access for UID %d\n",bprm->filename,att, uid.val);
      	return -EPERM;
      }
  }
  printk(KERN_INFO "[Execsec] call [whitelist_check] of %s  no xattr found for UID %d \n",bprm->filename,uid.val);
  //return -EPERM;
  return 0;

}


